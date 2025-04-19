import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "../auth/[...nextauth]/route";
import prisma from "@/lib/prisma";
import { createUser } from "@/lib/seed";

export async function GET(request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Only super admins can see all users
    if (session.user.role !== "SUPER_ADMIN") {
      return NextResponse.json(
        { error: "You do not have permission to view all users" },
        { status: 403 }
      );
    }

    // Check for role filter in query params
    const { searchParams } = new URL(request.url);
    const role = searchParams.get("role");

    let whereClause = {};
    if (role) {
      whereClause.role = role;
    }

    const users = await prisma.adminUser.findMany({
      where: whereClause,
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
      orderBy: {
        name: "asc",
      },
    });

    return NextResponse.json(users);
  } catch (error) {
    console.error("Error fetching admin users:", error);
    return NextResponse.json(
      { error: "Failed to fetch admin users" },
      { status: 500 }
    );
  }
}

export async function POST(request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Only super admins can create users
    if (session.user.role !== "SUPER_ADMIN") {
      return NextResponse.json(
        { error: "You do not have permission to create admin users" },
        { status: 403 }
      );
    }

    const data = await request.json();
    const { name, email, password, role, centers } = data;

    // Check if email already exists
    const existingUser = await prisma.adminUser.findUnique({
      where: { email },
    });
    
    if (existingUser) {
      return NextResponse.json(
        { error: "Email already in use" },
        { status: 400 }
      );
    }

    // Create user
    const user = await createUser({
      name,
      email,
      password,
      role,
    });

    // If centers are provided and user is a CENTER_MANAGER, connect them
    if (centers && centers.length > 0 && role === "CENTER_MANAGER") {
      // Update centers to connect the manager
      await Promise.all(
        centers.map(async (centerId) => {
          await prisma.center.update({
            where: { id: centerId },
            data: { managerId: user.id },
          });
        })
      );
    }

    // Return user without password
    const { password: _, ...userWithoutPassword } = user;
    return NextResponse.json(userWithoutPassword, { status: 201 });
  } catch (error) {
    console.error("Error creating admin user:", error);
    return NextResponse.json(
      { error: "Failed to create admin user" },
      { status: 500 }
    );
  }
} 