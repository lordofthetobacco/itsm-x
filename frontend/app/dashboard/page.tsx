"use client";

import { ProtectedRoute } from "../components/protected-route";
import { useAuth } from "../context/auth-context";
import Button from "../components/button";

function Dashboard() {
  const { user, permissions, hasPermission } = useAuth();

  return (
    <ProtectedRoute>
      <div className="min-h-screen flex flex-col">
        <div className="flex-1 p-8">
          <h2 className="text-3xl font-bold mb-6">Dashboard</h2>
          <div className="grid gap-6">
            <div className="bg-card border border-border rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4">User Information</h3>
              {user && (
                <div className="space-y-2">
                  <p>
                    <span className="font-medium">Name:</span> {user.name}
                  </p>
                  <p>
                    <span className="font-medium">Email:</span> {user.email}
                  </p>
                  {user.role && (
                    <p>
                      <span className="font-medium">Role:</span>{" "}
                      {user.role.name}
                    </p>
                  )}
                </div>
              )}
            </div>
            <div className="bg-card border border-border rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4">Permissions</h3>
              <div className="flex flex-wrap gap-2">
                {permissions.length > 0 ? (
                  permissions.map((perm) => (
                    <span
                      key={perm}
                      className="bg-primary/10 text-primary px-3 py-1 rounded-md text-sm"
                    >
                      {perm}
                    </span>
                  ))
                ) : (
                  <p className="text-muted-foreground">No permissions loaded</p>
                )}
              </div>
            </div>
            <div className="bg-card border border-border rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4">Quick Actions</h3>
              <div className="flex flex-wrap gap-4">
                {hasPermission("tickets.read") && (
                  <Button onClick={() => (window.location.href = "/tickets")}>
                    View Tickets
                  </Button>
                )}
                {hasPermission("users.read") && (
                  <Button onClick={() => (window.location.href = "/users")}>
                    View Users
                  </Button>
                )}
                {hasPermission("tickets.create") && (
                  <Button
                    onClick={() => (window.location.href = "/tickets/new")}
                  >
                    Create Ticket
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}

export default Dashboard;
