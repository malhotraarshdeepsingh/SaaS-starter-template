import { authMiddleware, clerkClient } from "@clerk/nextjs/server";
import { NextRequest, NextResponse } from "next/server";

const publicRoutes = ["/", "/api/webhook/register", "/sign-up", "/sign-in"];

export default authMiddleware({
  publicRoutes,
  async afterAuth(auth, req) {
    // Redirect to sign-in page if not authenticated and not on public routes
    if (!auth.userId && !publicRoutes.includes(req.nextUrl.pathname))
      return NextResponse.redirect(new URL("/sign-in", req.url));

    if (auth.userId) {
      try {
        const user = await clerkClient.users.getUser(auth.userId);
        const role = user.publicMetadata.role as string | undefined;
  
        // Redirect to admin dashboard if authenticated and user is admin
        if (role === "admin" && req.nextUrl.pathname === "/dashboard") {
          return NextResponse.redirect(new URL("/admin/dashboard", req.url));
        }
  
        // Redirect to dashboard if authenticated and user is not admin and trying to access admin routes
        if (role !== "admin" && req.nextUrl.pathname.startsWith("/admin")) {
          return NextResponse.redirect(new URL("/dashboard", req.url));
        }
  
        // Redirect auth user trying to access public routes
        if (publicRoutes.includes(req.nextUrl.pathname)) {
          return NextResponse.redirect(
            new URL(role === "admin" ? "/admin/dashboard" : "/dashboard",req.url)
          );
        }
      } catch (error) {
        console.error(error);
        return NextResponse.redirect(new URL("/error", req.url));
      }
    }
  },
});

export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run for API routes
    "/(api|trpc)(.*)",
  ],
};
