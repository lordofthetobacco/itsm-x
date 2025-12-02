function Card({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-card rounded-lg shadow-md border border-border w-full max-w-md ${className}`}
    >
      {children}
    </div>
  );
}

export default Card;
