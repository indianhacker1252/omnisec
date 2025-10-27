import { cn } from "@/lib/utils";

interface StatusIndicatorProps {
  label: string;
  value: string | number;
  status?: "normal" | "warning" | "critical" | "success";
  className?: string;
}

export const StatusIndicator = ({
  label,
  value,
  status = "normal",
  className,
}: StatusIndicatorProps) => {
  const statusColors = {
    normal: "text-foreground",
    warning: "text-warning",
    critical: "text-destructive",
    success: "text-success",
  };

  const dotColors = {
    normal: "bg-muted-foreground",
    warning: "bg-warning animate-pulse",
    critical: "bg-destructive animate-pulse",
    success: "bg-success",
  };

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className={cn("h-2 w-2 rounded-full", dotColors[status])} />
      <div className="flex flex-col">
        <span className="text-xs text-muted-foreground font-mono">{label}</span>
        <span className={cn("text-sm font-semibold font-mono", statusColors[status])}>
          {value}
        </span>
      </div>
    </div>
  );
};
