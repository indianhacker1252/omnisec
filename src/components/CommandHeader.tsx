/**
 * OmniSec™ Command Header
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { Bell, Settings, Terminal, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export const CommandHeader = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [alertCount] = useState(3);

  const alerts = [
    { id: 1, message: "Critical: SQL injection detected on target.com", severity: "critical" },
    { id: 2, message: "Warning: Unusual network traffic pattern", severity: "high" },
    { id: 3, message: "Info: Scan completed successfully", severity: "info" },
  ];

  const handleClearAlerts = () => {
    toast({
      title: "Alerts Cleared",
      description: "All notifications have been cleared",
    });
  };

  const handleSignOut = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      toast({
        title: "Error",
        description: "Failed to sign out",
        variant: "destructive",
      });
    } else {
      toast({
        title: "Signed Out",
        description: "You have been signed out successfully",
      });
      navigate("/auth");
    }
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <Terminal className="h-6 w-6 text-cyber-green" />
          <div>
            <h1 className="text-lg font-bold font-mono leading-none">
              OmniSec<sup className="text-[8px] align-super">TM</sup>
            </h1>
            <p className="text-[10px] text-muted-foreground">
              © HARSH MALIK
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <Bell className="h-5 w-5" />
                {alertCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-[10px]"
                  >
                    {alertCount}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel className="flex items-center justify-between">
                <span>Security Alerts</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs"
                  onClick={handleClearAlerts}
                >
                  Clear All
                </Button>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {alerts.map((alert) => (
                <DropdownMenuItem key={alert.id} className="flex flex-col items-start gap-1 p-3">
                  <div className="flex items-center gap-2 w-full">
                    <Badge
                      variant={
                        alert.severity === "critical"
                          ? "destructive"
                          : alert.severity === "high"
                          ? "default"
                          : "secondary"
                      }
                      className="text-[10px]"
                    >
                      {alert.severity.toUpperCase()}
                    </Badge>
                  </div>
                  <span className="text-sm">{alert.message}</span>
                </DropdownMenuItem>
              ))}
              {alerts.length === 0 && (
                <div className="p-4 text-center text-sm text-muted-foreground">
                  No active alerts
                </div>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/settings")}
          >
            <Settings className="h-5 w-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={handleSignOut}
            title="Sign Out"
          >
            <LogOut className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  );
};
