import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "../../auth/[...nextauth]/route";
import prisma from "@/lib/prisma";
import { hash } from "bcrypt";

export async function GET(request, { params }) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Only super admins or the user themselves can view user details
    if (session.user.role !== "SUPER_ADMIN" && session.user.id !== params.id) {
      return NextResponse.json(
        { error: "You do not have permission to view this user" },
        { status: 403 }
      );
    }

    const user = await prisma.adminUser.findUnique({
      where: {
        id: params.id,
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        centers: {
          select: {
            id: true,
            name: true,
          },
        },
        createdAt: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    return NextResponse.json(user);
  } catch (error) {
    console.error("Error fetching admin user:", error);
    return NextResponse.json(
      { error: "Failed to fetch admin user" },
      { status: 500 }
    );
  }
}

export async function PUT(request, { params }) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Only super admins or the user themselves can update user details
    if (session.user.role !== "SUPER_ADMIN" && session.user.id !== params.id) {
      return NextResponse.json(
        { error: "You do not have permission to update this user" },
        { status: 403 }
      );
    }

    const data = await request.json();
    const { name, email, password, role, centers } = data;

    // If the user is updating themselves, they can't change their own role
    if (session.user.id === params.id && session.user.role !== role) {
      return NextResponse.json(
        { error: "You cannot change your own role" },
        { status: 403 }
      );
    }

    // Check if email already exists (but not for the current user)
    const existingUser = await prisma.adminUser.findFirst({
      where: {
        email,
        id: {
          not: params.id,
        },
      },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "Email already in use" },
        { status: 400 }
      );
    }

    // Prepare update data
    const updateData = {
      name,
      email,
      ...(role && session.user.role === "SUPER_ADMIN" ? { role } : {}),
    };

    // If password is provided, hash it
    if (password) {
      updateData.password = await hash(password, 10);
    }

    // Update user
    const user = await prisma.adminUser.update({
      where: {
        id: params.id,
      },
      data: updateData,
    });

    // If centers are provided and the user is a CENTER_MANAGER
    if (centers && session.user.role === "SUPER_ADMIN") {
      // First, remove the user as manager from all centers
      await prisma.center.updateMany({
        where: {
          managerId: params.id,
        },
        data: {
          managerId: null,
        },
      });

      // Then, set the user as manager for the selected centers
      if (centers.length > 0 && role === "CENTER_MANAGER") {
        await Promise.all(
          centers.map(async (centerId) => {
            await prisma.center.update({
              where: { id: centerId },
              data: { managerId: params.id },
            });
          })
        );
      }
    }

    // Return user without password
    const { password: _, ...userWithoutPassword } = user;
    return NextResponse.json(userWithoutPassword);
  } catch (error) {
    console.error("Error updating admin user:", error);
    return NextResponse.json(
      { error: "Failed to update admin user" },
      { status: 500 }
    );
  }
}

export async function DELETE(request, { params }) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Only super admins can delete users
    if (session.user.role !== "SUPER_ADMIN") {
      return NextResponse.json(
        { error: "You do not have permission to delete users" },
        { status: 403 }
      );
    }

    // Can't delete yourself
    if (session.user.id === params.id) {
      return NextResponse.json(
        { error: "You cannot delete your own account" },
        { status: 400 }
      );
    }

    // First, remove user as manager from any centers
    await prisma.center.updateMany({
      where: {
        managerId: params.id,
      },
      data: {
        managerId: null,
      },
    });

    // Delete the user
    await prisma.adminUser.delete({
      where: {
        id: params.id,
      },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error("Error deleting admin user:", error);
    return NextResponse.json(
      { error: "Failed to delete admin user" },
      { status: 500 }
    );
  }
} 