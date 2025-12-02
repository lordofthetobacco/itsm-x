export const API_BASE_URL = "http://localhost:8080";

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  role_id?: number;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: number;
    name: string;
    email: string;
    role_id: number;
    role?: {
      id: number;
      name: string;
      description: string;
    };
    created_at: string;
  };
}

export interface RefreshResponse {
  access_token: string;
}

export interface PermissionsResponse {
  permissions: string[];
}

export interface User {
  id: number;
  name: string;
  email: string;
  role_id: number;
  avatar_url?: string;
  role?: {
    id: number;
    name: string;
    description: string;
  };
  created_at: string;
}

async function getAccessToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("access_token");
}

async function getRefreshToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("refresh_token");
}

async function setTokens(
  accessToken: string,
  refreshToken: string
): Promise<void> {
  if (typeof window === "undefined") return;
  localStorage.setItem("access_token", accessToken);
  localStorage.setItem("refresh_token", refreshToken);
}

async function clearTokens(): Promise<void> {
  if (typeof window === "undefined") return;
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = await getRefreshToken();
  if (!refreshToken) return null;

  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      // Only clear tokens if refresh token is invalid (401/403)
      // Don't clear on network errors or server errors
      if (response.status === 401 || response.status === 403) {
        await clearTokens();
      }
      return null;
    }

    const data: RefreshResponse = await response.json();
    await setTokens(data.access_token, refreshToken);
    return data.access_token;
  } catch (error) {
    // Don't clear tokens on network errors - let user retry
    console.error("Token refresh error:", error);
    return null;
  }
}

async function fetchWithAuth(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  let accessToken = await getAccessToken();

  if (!accessToken) {
    accessToken = await refreshAccessToken();
    if (!accessToken) {
      throw new Error("Not authenticated");
    }
  }

  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${accessToken}`);
  // Only set Content-Type if not already set (for multipart/form-data, etc.)
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
    });
  } catch (networkError) {
    // Network error (CORS, connection refused, etc.)
    console.error("Network error fetching:", url, networkError);
    throw new Error(
      `Network error: ${
        networkError instanceof Error
          ? networkError.message
          : String(networkError)
      }`
    );
  }

  if (response.status === 401) {
    accessToken = await refreshAccessToken();
    if (!accessToken) {
      throw new Error("Not authenticated");
    }

    headers.set("Authorization", `Bearer ${accessToken}`);
    try {
      response = await fetch(url, {
        ...options,
        headers,
      });
    } catch (networkError) {
      console.error("Network error on retry:", url, networkError);
      throw new Error(
        `Network error: ${
          networkError instanceof Error
            ? networkError.message
            : String(networkError)
        }`
      );
    }

    // If still 401 after refresh, the refresh token is invalid
    if (response.status === 401) {
      await clearTokens();
      throw new Error("Not authenticated");
    }
  }

  return response;
}

export async function login(credentials: LoginRequest): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Login failed");
  }

  const data: AuthResponse = await response.json();
  await setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function register(
  userData: RegisterRequest
): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(userData),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Registration failed");
  }

  const data: AuthResponse = await response.json();
  await setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function logout(): Promise<void> {
  const refreshToken = await getRefreshToken();
  if (refreshToken) {
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch (error) {
      console.error("Logout error:", error);
    }
  }
  await clearTokens();
}

export async function getCurrentUser(): Promise<User> {
  try {
    const response = await fetchWithAuth(`${API_BASE_URL}/auth/me`);
    if (!response.ok) {
      // Try to get error message from response
      let errorMessage = `HTTP ${response.status}`;
      const contentType = response.headers.get("content-type");

      if (contentType && contentType.includes("application/json")) {
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          // Response is not valid JSON, use status text
          errorMessage = response.statusText || errorMessage;
        }
      } else {
        // Try to get text response
        try {
          const text = await response.text();
          if (text) errorMessage = text;
        } catch {
          errorMessage = response.statusText || errorMessage;
        }
      }

      throw new Error(`Failed to fetch current user: ${errorMessage}`);
    }
    return response.json();
  } catch (error) {
    // Re-throw with more context if it's already an Error
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(`Failed to fetch current user: ${String(error)}`);
  }
}

export async function getPermissions(): Promise<string[]> {
  try {
    const response = await fetchWithAuth(`${API_BASE_URL}/auth/permissions`);
    if (!response.ok) {
      // Try to get error message from response
      let errorMessage = `HTTP ${response.status}`;
      const contentType = response.headers.get("content-type");

      if (contentType && contentType.includes("application/json")) {
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          errorMessage = response.statusText || errorMessage;
        }
      } else {
        try {
          const text = await response.text();
          if (text) errorMessage = text;
        } catch {
          errorMessage = response.statusText || errorMessage;
        }
      }

      throw new Error(`Failed to fetch permissions: ${errorMessage}`);
    }
    const data: PermissionsResponse = await response.json();
    return data.permissions;
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(`Failed to fetch permissions: ${String(error)}`);
  }
}

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetchWithAuth(`${API_BASE_URL}${endpoint}`, options);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Request failed");
  }
  return response.json();
}
