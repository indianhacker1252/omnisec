import { Card } from "@/components/ui/card";
import { StatusIndicator } from "./StatusIndicator";
import { Shield, Cpu, HardDrive, Network } from "lucide-react";

export const SystemStatus = () => {
  return (
    <Card className="p-6 bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-6">
        <Shield className="h-5 w-5 text-cyber-cyan" />
        <h3 className="font-semibold font-mono">System Status</h3>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <StatusIndicator
          label="CPU Load"
          value="23%"
          status="success"
        />
        <StatusIndicator
          label="Memory"
          value="4.2GB / 16GB"
          status="normal"
        />
        <StatusIndicator
          label="Active Scans"
          value="3"
          status="normal"
        />
        <StatusIndicator
          label="Threats Detected"
          value="12"
          status="warning"
        />
        <StatusIndicator
          label="Network I/O"
          value="245 MB/s"
          status="success"
        />
        <StatusIndicator
          label="DB Queries"
          value="1.2K/min"
          status="normal"
        />
      </div>

      <div className="mt-6 pt-6 border-t border-border/50">
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center">
            <Cpu className="h-5 w-5 mx-auto mb-2 text-cyber-cyan" />
            <p className="text-xs text-muted-foreground font-mono">8 Cores</p>
          </div>
          <div className="text-center">
            <HardDrive className="h-5 w-5 mx-auto mb-2 text-cyber-purple" />
            <p className="text-xs text-muted-foreground font-mono">2TB SSD</p>
          </div>
          <div className="text-center">
            <Network className="h-5 w-5 mx-auto mb-2 text-success" />
            <p className="text-xs text-muted-foreground font-mono">10Gbps</p>
          </div>
          <div className="text-center">
            <Shield className="h-5 w-5 mx-auto mb-2 text-cyber-red" />
            <p className="text-xs text-muted-foreground font-mono">Lab Mode</p>
          </div>
        </div>
      </div>
    </Card>
  );
};
