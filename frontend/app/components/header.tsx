"use client";

import { useAuth } from "../context/auth-context";
import ProfileButton from "./profile";
import Button from "./button";
import { useRouter } from "next/navigation";

export default function Header() {
  const { user, isAuthenticated, isLoading, logout, hasPermission } = useAuth();
  const router = useRouter();

  return (
    <div className="sticky top-0 z-50 border-b border-border bg-background">
      <div className="flex items-center justify-between p-4">
        <h1 className="text-2xl font-bold">ITSM X</h1>
        <div className="flex items-center gap-4">
          {!isLoading && isAuthenticated && user && (
            <>
              <nav className="flex items-center gap-4 animate-[fadeInSlide_0.3s_ease-in-out]">
                {hasPermission("tickets.read") && (
                  <button
                    onClick={() => router.push("/tickets")}
                    className="text-sm hover:text-primary transition-colors"
                  >
                    Tickets
                  </button>
                )}
                {hasPermission("users.read") && (
                  <button
                    onClick={() => router.push("/users")}
                    className="text-sm hover:text-primary transition-colors"
                  >
                    Users
                  </button>
                )}
                {hasPermission("roles.read") && (
                  <button
                    onClick={() => router.push("/roles")}
                    className="text-sm hover:text-primary transition-colors"
                  >
                    Roles
                  </button>
                )}
                <div className="w-px h-6 bg-border"></div>
              </nav>
              <div className="flex items-center gap-4 animate-[fadeInSlide_0.3s_ease-in-out_0.1s_both]">
                {user && <ProfileButton user={user} />}
                <Button onClick={logout}>Logout</Button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

