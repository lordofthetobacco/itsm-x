"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import {
  login,
  register,
  logout,
  getPermissions,
  getCurrentUser,
  User,
} from "../lib/api";

interface AuthContextType {
  user: User | null;
  permissions: string[];
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    name: string,
    email: string,
    password: string,
    roleId?: number
  ) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  refreshPermissions: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  const persistUser = (value: User | null) => {
    if (typeof window === "undefined") return;
    if (value) {
      localStorage.setItem("user", JSON.stringify(value));
    } else {
      localStorage.removeItem("user");
    }
  };

  const persistPermissions = (value: string[]) => {
    if (typeof window === "undefined") return;
    if (value.length > 0) {
      localStorage.setItem("permissions", JSON.stringify(value));
    } else {
      localStorage.removeItem("permissions");
    }
  };

  const hydrateFromStorage = () => {
    if (typeof window === "undefined") return;

    const storedUser = localStorage.getItem("user");
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch {
        localStorage.removeItem("user");
      }
    }

    const storedPermissions = localStorage.getItem("permissions");
    if (storedPermissions) {
      try {
        const parsed = JSON.parse(storedPermissions);
        if (Array.isArray(parsed)) {
          setPermissions(parsed);
        } else {
          localStorage.removeItem("permissions");
        }
      } catch {
        localStorage.removeItem("permissions");
      }
    }
  };

  useEffect(() => {
    hydrateFromStorage();
    checkAuth();
  }, []);

  async function checkAuth() {
    try {
      if (typeof window === "undefined") {
        setIsLoading(false);
        return;
      }

      const refreshToken = localStorage.getItem("refresh_token");

      // If we have no refresh token, we're not authenticated
      if (!refreshToken) {
        persistUser(null);
        persistPermissions([]);
        setUser(null);
        setPermissions([]);
        setIsLoading(false);
        return;
      }

      // Try to fetch user and permissions
      // fetchWithAuth will automatically refresh the token if needed
      try {
        const [freshUser, freshPerms] = await Promise.all([
          getCurrentUser(),
          getPermissions(),
        ]);

        setUser(freshUser);
        persistUser(freshUser);
        setPermissions(freshPerms);
        persistPermissions(freshPerms);
      } catch (fetchError) {
        // If fetchWithAuth fails, check if it's an auth error
        const errorMessage =
          fetchError instanceof Error ? fetchError.message : String(fetchError);

        // Only clear tokens if we get "Not authenticated" error or auth-related errors
        // This means refresh token is invalid
        if (
          errorMessage === "Not authenticated" ||
          errorMessage.includes("401") ||
          errorMessage.includes("403") ||
          errorMessage.includes("Unauthorized")
        ) {
          console.log(
            "Clearing tokens due to authentication failure:",
            errorMessage
          );
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          persistUser(null);
          persistPermissions([]);
          setUser(null);
          setPermissions([]);
        } else {
          // For network errors or other issues, keep tokens
          // User might just need to retry
          console.error("Auth fetch error (keeping tokens):", errorMessage);
        }
      }
    } catch (error) {
      // Only clear tokens on critical errors
      console.error("Auth check error:", error);
    } finally {
      setIsLoading(false);
    }
  }

  async function handleLogin(email: string, password: string) {
    try {
      const response = await login({ email, password });
      setUser(response.user);
      persistUser(response.user);
      await refreshPermissions();
      router.push("/dashboard");
    } catch (error) {
      throw error;
    }
  }

  async function handleRegister(
    name: string,
    email: string,
    password: string,
    roleId?: number
  ) {
    try {
      const response = await register({
        name,
        email,
        password,
        role_id: roleId,
      });
      setUser(response.user);
      persistUser(response.user);
      await refreshPermissions();
      router.push("/dashboard");
    } catch (error) {
      throw error;
    }
  }

  async function handleLogout() {
    try {
      await logout();
      setUser(null);
      setPermissions([]);
      persistUser(null);
      persistPermissions([]);
      router.push("/");
    } catch (error) {
      console.error("Logout error:", error);
      setUser(null);
      setPermissions([]);
      persistUser(null);
      persistPermissions([]);
      router.push("/");
    }
  }

  async function refreshPermissions() {
    try {
      const perms = await getPermissions();
      setPermissions(perms);
      persistPermissions(perms);
    } catch (error) {
      console.error("Failed to refresh permissions:", error);
    }
  }

  function hasPermission(permission: string): boolean {
    return permissions.includes(permission);
  }

  // Consider authenticated if we have a user OR if we're still loading (to prevent premature redirects)
  // Also check if we have tokens in localStorage as a fallback
  const hasTokens =
    typeof window !== "undefined" &&
    !!(
      localStorage.getItem("access_token") ||
      localStorage.getItem("refresh_token")
    );
  const isAuthenticated =
    !!user || (isLoading && hasTokens) || permissions.length > 0;

  return (
    <AuthContext.Provider
      value={{
        user,
        permissions,
        isLoading,
        isAuthenticated,
        login: handleLogin,
        register: handleRegister,
        logout: handleLogout,
        hasPermission,
        refreshPermissions,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
