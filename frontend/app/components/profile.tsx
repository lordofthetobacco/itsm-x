"use client";

import { User, API_BASE_URL } from "../lib/api";

export default function ProfileButton({ user }: { user: User }) {
  const avatarUrl = user.avatar_url
    ? `${API_BASE_URL}${user.avatar_url}`
    : null;

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <div className="relative">
      {avatarUrl ? (
        <img
          src={avatarUrl}
          alt={user.name}
          className="w-10 h-10 rounded-full object-cover border border-border"
          onError={(e) => {
            e.currentTarget.style.display = "none";
            const fallback = e.currentTarget.nextElementSibling as HTMLElement;
            if (fallback) fallback.style.display = "flex";
          }}
        />
      ) : null}
      <div
        className={`w-10 h-10 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-semibold text-sm border border-border ${
          avatarUrl ? "hidden" : "flex"
        }`}
      >
        {getInitials(user.name)}
      </div>
    </div>
  );
}
