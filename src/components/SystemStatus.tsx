import { Card } from "@/components/ui/card";
import { StatusIndicator } from "./StatusIndicator";
import { Shield, Cpu, HardDrive, Network } from "lucide-react";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

interface BackendStatus {
  time: string;
  aiEnabled: boolean;
  shodanConfigured: boolean;
  nvdConfigured: boolean;
}

export const SystemStatus = () => {
  const [status, setStatus] = useState<BackendStatus | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const { data } = await supabase.functions.invoke('status');
        setStatus(data as BackendStatus);
      } catch (e) {
        console.error(e);
      }
    })();
  }, []);

  return (
    <Card className="p-6 bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-6">
        <Shield className="h-5 w-5 text-cyber-cyan" />
        <h3 className="font-semibold font-mono">System Status</h3>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <StatusIndicator
          label="AI Gateway"
          value={status?.aiEnabled ? "Online" : "Offline"}
          status={status?.aiEnabled ? "success" : "warning"}
        />
        <StatusIndicator
          label="Shodan"
          value={status?.shodanConfigured ? "Configured" : "Missing Key"}
          status={status?.shodanConfigured ? "normal" : "warning"}
        />
        <StatusIndicator
          label="NVD"
          value={status?.nvdConfigured ? "Configured" : "Optional"}
          status={status?.nvdConfigured ? "normal" : "success"}
        />
        <StatusIndicator
          label="Server Time"
          value={status?.time ? new Date(status.time).toLocaleTimeString() : "--"}
          status="normal"
        />
      </div>

      <div className="mt-6 pt-6 border-t border-border/50">
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center">
            <Cpu className="h-5 w-5 mx-auto mb-2 text-cyber-cyan" />
            <p className="text-xs text-muted-foreground font-mono">Live backend</p>
          </div>
          <div className="text-center">
            <HardDrive className="h-5 w-5 mx-auto mb-2 text-cyber-purple" />
            <p className="text-xs text-muted-foreground font-mono">Secure secrets</p>
          </div>
          <div className="text-center">
            <Network className="h-5 w-5 mx-auto mb-2 text-success" />
            <p className="text-xs text-muted-foreground font-mono">Public functions</p>
          </div>
          <div className="text-center">
            <Shield className="h-5 w-5 mx-auto mb-2 text-cyber-red" />
            <p className="text-xs text-muted-foreground font-mono">Safe usage</p>
          </div>
        </div>
      </div>
    </Card>
  );
};
