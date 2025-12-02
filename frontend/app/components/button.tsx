function Button({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      className="bg-primary text-primary-foreground p-2 rounded-md hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity w-full"
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

export default Button;
