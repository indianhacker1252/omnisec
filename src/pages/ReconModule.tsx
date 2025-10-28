import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Search, Activity, Server, Globe, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface ScanResult {
  id: string;
  host: string;
  ports: number[];
  services: string[];
  status: "online" | "offline";
  timestamp: string;
}

const ReconModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);

  const startScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Invalid Target",
        description: "Please enter a valid IP address or hostname",
        variant: "destructive",
      });
      return;
    }

    setScanning(true);
    toast({
      title: "Scan Started",
      description: `Initiating reconnaissance on ${target}`,
    });

    try {
      const { data, error } = await supabase.functions.invoke('recon', {
        body: { target },
      });
      if (error) throw error;

      const api = data as any;
      const mapped: ScanResult = {
        id: Date.now().toString(),
        host: api.host,
        ports: (api.ports || []).map((p: any) => Number(p.port)),
        services: (api.ports || []).map((p: any) => p.service || p.product || ''),
        status: api.status || 'online',
        timestamp: new Date(api.timestamp || Date.now()).toLocaleString(),
      };

      setResults((prev) => [mapped, ...prev]);
      toast({
        title: "Scan Complete",
        description: `Found ${mapped.ports.length} open ports on ${api.host}`,
      });
    } catch (e) {
      console.error(e);
      toast({
        title: "Scan Failed",
        description: e instanceof Error ? e.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />

      <main className="container mx-auto px-6 py-8">
        <Button
          variant="ghost"
          onClick={() => navigate("/")}
          className="mb-6 gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Search className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">
              Reconnaissance Module
            </h1>
          </div>
          <p className="text-muted-foreground">
            Network mapping, asset discovery, and OSINT gathering
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scan Controls */}
          <Card className="lg:col-span-1 p-6 bg-card/50 backdrop-blur-sm">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Activity className="h-5 w-5 text-cyber-cyan" />
              Scan Configuration
            </h3>

            <div className="space-y-4">
              <div>
                <label className="text-sm font-mono mb-2 block">Target</label>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.1 or example.com"
                  className="font-mono bg-background/50"
                  disabled={scanning}
                />
              </div>

              <Button
                onClick={startScan}
                disabled={scanning}
                className="w-full bg-cyber-cyan hover:bg-cyber-cyan/80 text-background"
              >
                {scanning ? (
                  <>
                    <Activity className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>

              <div className="pt-4 border-t border-border/50 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground font-mono">
                    Mode
                  </span>
                  <Badge variant="secondary">Lab Safe</Badge>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground font-mono">
                    Depth
                  </span>
                  <span className="font-mono">Standard</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground font-mono">
                    Threads
                  </span>
                  <span className="font-mono">16</span>
                </div>
              </div>
            </div>
          </Card>

          {/* Results */}
          <Card className="lg:col-span-2 p-6 bg-card/50 backdrop-blur-sm">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Server className="h-5 w-5 text-cyber-purple" />
              Scan Results
            </h3>

            {results.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-center">
                <Globe className="h-16 w-16 text-muted-foreground mb-4 opacity-20" />
                <p className="text-muted-foreground font-mono">
                  No scans performed yet
                </p>
                <p className="text-sm text-muted-foreground mt-2">
                  Enter a target and click Start Scan
                </p>
              </div>
            ) : (
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {results.map((result) => (
                    <Card
                      key={result.id}
                      className="p-4 bg-background/50 border-cyber-cyan/30"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h4 className="font-semibold font-mono text-lg">
                            {result.host}
                          </h4>
                          <p className="text-xs text-muted-foreground font-mono">
                            {result.timestamp}
                          </p>
                        </div>
                        <Badge
                          variant={
                            result.status === "online"
                              ? "default"
                              : "destructive"
                          }
                        >
                          {result.status}
                        </Badge>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <span className="text-sm text-muted-foreground font-mono">
                            Open Ports:
                          </span>
                          <div className="flex flex-wrap gap-2 mt-1">
                            {result.ports.map((port, idx) => (
                              <Badge
                                key={port}
                                variant="secondary"
                                className="font-mono"
                              >
                                {port} • {result.services[idx]}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            )}
          </Card>
        </div>
      </main>
    </div>
  );
};

export default ReconModule;
