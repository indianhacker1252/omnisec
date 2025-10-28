import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Bug, Activity, AlertTriangle, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Vulnerability {
  id: string;
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  cvss: number;
  timestamp: string;
}

const VulnModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);

  const startScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Invalid Target",
        description: "Please enter a valid URL or IP address",
        variant: "destructive",
      });
      return;
    }

    setScanning(true);
    toast({
      title: "Vulnerability Scan Started",
      description: `Analyzing ${target} for known vulnerabilities`,
    });

    try {
      const { data, error } = await supabase.functions.invoke('vulnintel', {
        body: { query: target },
      });
      if (error) throw error;
      const payload = data as any;
      const mapped: Vulnerability[] = (payload.vulnerabilities || []).map((v: any) => ({
        id: v.id,
        cve: v.cve,
        severity: (v.severity || 'unknown') as any,
        title: v.title,
        description: v.description,
        cvss: v.cvss ?? 0,
        timestamp: new Date(v.timestamp || Date.now()).toLocaleString(),
      }));
      setVulnerabilities((prev) => [...mapped, ...prev]);
      toast({ title: "Scan Complete", description: `Found ${mapped.length} vulnerabilities` });
    } catch (e) {
      console.error(e);
      toast({ title: "Scan Failed", description: e instanceof Error ? e.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-cyber-red border-cyber-red";
      case "high":
        return "text-warning border-warning";
      case "medium":
        return "text-cyber-purple border-cyber-purple";
      case "low":
        return "text-cyber-cyan border-cyber-cyan";
      default:
        return "";
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
            <Bug className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">
              Vulnerability Intelligence
            </h1>
          </div>
          <p className="text-muted-foreground">
            CVE correlation and exploit database integration
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scan Controls */}
          <Card className="lg:col-span-1 p-6 bg-card/50 backdrop-blur-sm">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Activity className="h-5 w-5 text-cyber-purple" />
              Scan Configuration
            </h3>

            <div className="space-y-4">
              <div>
                <label className="text-sm font-mono mb-2 block">Target</label>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com"
                  className="font-mono bg-background/50"
                  disabled={scanning}
                />
              </div>

              <Button
                onClick={startScan}
                disabled={scanning}
                className="w-full bg-cyber-purple hover:bg-cyber-purple/80 text-background"
              >
                {scanning ? (
                  <>
                    <Activity className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Bug className="h-4 w-4 mr-2" />
                    Start Vulnerability Scan
                  </>
                )}
              </Button>

              <div className="pt-4 border-t border-border/50">
                <h4 className="text-sm font-semibold mb-3 font-mono">
                  Statistics
                </h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-cyber-red font-mono">Critical</span>
                    <span className="font-mono">
                      {
                        vulnerabilities.filter((v) => v.severity === "critical")
                          .length
                      }
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-warning font-mono">High</span>
                    <span className="font-mono">
                      {
                        vulnerabilities.filter((v) => v.severity === "high")
                          .length
                      }
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-cyber-purple font-mono">Medium</span>
                    <span className="font-mono">
                      {
                        vulnerabilities.filter((v) => v.severity === "medium")
                          .length
                      }
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-cyber-cyan font-mono">Low</span>
                    <span className="font-mono">
                      {
                        vulnerabilities.filter((v) => v.severity === "low")
                          .length
                      }
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Results */}
          <Card className="lg:col-span-2 p-6 bg-card/50 backdrop-blur-sm">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              Detected Vulnerabilities
            </h3>

            {vulnerabilities.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-center">
                <Bug className="h-16 w-16 text-muted-foreground mb-4 opacity-20" />
                <p className="text-muted-foreground font-mono">
                  No vulnerabilities found yet
                </p>
                <p className="text-sm text-muted-foreground mt-2">
                  Enter a target and start scanning
                </p>
              </div>
            ) : (
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {vulnerabilities.map((vuln) => (
                    <Card
                      key={vuln.id}
                      className={`p-4 bg-background/50 border ${getSeverityColor(
                        vuln.severity
                      )}`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge
                              variant="secondary"
                              className="font-mono text-xs"
                            >
                              {vuln.cve}
                            </Badge>
                            <Badge
                              variant={
                                vuln.severity === "critical"
                                  ? "destructive"
                                  : "secondary"
                              }
                              className="font-mono text-xs"
                            >
                              {vuln.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <h4 className="font-semibold text-lg mb-1">
                            {vuln.title}
                          </h4>
                          <p className="text-sm text-muted-foreground mb-2">
                            {vuln.description}
                          </p>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                            <span>CVSS: {vuln.cvss}</span>
                            <span>•</span>
                            <span>{vuln.timestamp}</span>
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

export default VulnModule;
