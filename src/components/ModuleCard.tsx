import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface ModuleCardProps {
  title: string;
  description: string;
  icon: LucideIcon;
  status: "active" | "idle" | "alert";
  onClick?: () => void;
  className?: string;
}

export const ModuleCard = ({
  title,
  description,
  icon: Icon,
  status,
  onClick,
  className,
}: ModuleCardProps) => {
  const statusColors = {
    active: "border-cyber-cyan shadow-[0_0_15px_rgba(0,255,255,0.3)]",
    idle: "border-border hover:border-cyber-purple/50",
    alert: "border-cyber-red shadow-[0_0_15px_rgba(255,0,0,0.3)]",
  };

  const statusBadge = {
    active: { label: "Active", variant: "default" as const },
    idle: { label: "Idle", variant: "secondary" as const },
    alert: { label: "Alert", variant: "destructive" as const },
  };

  return (
    <Card
      className={cn(
        "relative overflow-hidden transition-all duration-300 cursor-pointer group",
        "bg-card/50 backdrop-blur-sm",
        statusColors[status],
        "hover:scale-[1.02] hover:shadow-lg",
        className
      )}
      onClick={onClick}
    >
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-secondary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
      
      <div className="relative p-6">
        <div className="flex items-start justify-between mb-4">
          <div className={cn(
            "p-3 rounded-lg",
            status === "active" && "bg-cyber-cyan/10 text-cyber-cyan",
            status === "idle" && "bg-muted text-muted-foreground",
            status === "alert" && "bg-cyber-red/10 text-cyber-red"
          )}>
            <Icon className="h-6 w-6" />
          </div>
          <Badge variant={statusBadge[status].variant}>
            {statusBadge[status].label}
          </Badge>
        </div>

        <h3 className="text-xl font-semibold mb-2 font-mono">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
    </Card>
  );
};
