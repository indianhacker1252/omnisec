import { Shield, Activity, Bell, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";

export const CommandHeader = () => {
  const navigate = useNavigate();
  return (
    <header className="border-b border-border/50 bg-card/30 backdrop-blur-md sticky top-0 z-50">
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="h-8 w-8 text-cyber-cyan" />
                <div className="absolute inset-0 animate-glow" />
              </div>
              <div>
                <h1 className="text-2xl font-bold font-mono tracking-wider">
                  OMNI<span className="text-cyber-cyan">SEC</span>
                </h1>
                <p className="text-xs text-muted-foreground">Unified Security Intelligence Platform</p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-success animate-pulse" />
              <span className="text-sm font-mono">System Operational</span>
            </div>
            
            <Button 
              variant="ghost" 
              size="icon" 
              className="relative"
              onClick={() => {
                // Show alerts/notifications
                alert('🔔 Security Alerts:\n\n1. New CVE detected: CVE-2024-1234 (Critical)\n2. Suspicious activity on network\n3. Port scan detected from 192.168.1.x\n\nNavigate to modules for detailed analysis.');
              }}
              aria-label="View alerts"
            >
              <Bell className="h-5 w-5" />
              <Badge className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center" variant="destructive">
                3
              </Badge>
            </Button>

            <Button variant="ghost" size="icon" onClick={() => navigate('/settings')} aria-label="Open settings">
              <Settings className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
};
