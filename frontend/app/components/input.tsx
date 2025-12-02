function Input({
  type,
  placeholder,
  value,
  onChange,
  onKeyPress,
  disabled,
}: {
  type: string;
  placeholder: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onKeyPress?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  disabled?: boolean;
}) {
  return (
    <input
      type={type}
      placeholder={placeholder}
      className="w-full p-2 rounded-md border border-border bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed"
      value={value}
      onChange={onChange}
      onKeyPress={onKeyPress}
      disabled={disabled}
    />
  );
}

export default Input;
