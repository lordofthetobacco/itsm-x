"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Card from "./components/card";
import Input from "./components/input";
import Button from "./components/button";
import { useAuth } from "./context/auth-context";

export default function Home() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (isAuthenticated) {
      router.push("/dashboard");
    }
  }, [isAuthenticated, router]);

  const handleLogin = async () => {
    if (!email || !password) {
      setError("Please enter both email and password");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      setTimeout(() => {
        setError("");
      }, 3000);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleLogin();
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 flex items-center justify-center p-4">
        <Card className="gap-6 flex flex-col p-8">
          <div className="flex flex-col gap-2">
            <h2 className="text-2xl font-bold">Login</h2>
            <p className="text-muted-foreground">
              {error
                ? "Incorrect email or password"
                : "Login to your ITSM X account"}
            </p>
          </div>
          <div className="flex flex-col gap-4">
            <Input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading}
            />
            <Input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading}
            />
            {error && <div className="text-destructive text-sm">{error}</div>}
            <Button onClick={handleLogin} disabled={isLoading}>
              {isLoading ? "Logging in..." : "Login"}
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
