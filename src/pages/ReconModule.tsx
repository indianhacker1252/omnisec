import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Search, Activity, Server, Globe, ArrowLeft, FileText, History, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useScanHistory } from "@/hooks/useScanHistory";
import { ReportGenerator } from "@/components/ReportGenerator";

interface ScanResult {
  id: string;
  host: string;
  ports: number[];
  services: string[];
  status: "online" | "offline";
  timestamp: string;
  mitre?: string;
}

const ReconModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { logScan, completeScan, createAlert, saveReport, getModuleHistory, getModuleReports } = useScanHistory();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);

  const loadHistory = async () => {
    const h = await getModuleHistory('recon');
    const r = await getModuleReports('recon');
    setHistory(h);
    setReports(r);
  };

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

    // Log scan start
    const scanId = await logScan({
      module: 'recon',
      scanType: 'Network Reconnaissance',
      target
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
        mitre: 'T1046 - Network Service Discovery'
      };

      setResults((prev) => [mapped, ...prev]);
      
      // Complete scan with findings
      if (scanId) {
        await completeScan(scanId, {
          status: 'completed',
          findingsCount: mapped.ports.length,
          report: { host: mapped.host, ports: mapped.ports, services: mapped.services }
        });
      }

      // Create alert if critical ports found
      const criticalPorts = [22, 23, 3389, 445, 1433, 3306];
      const foundCritical = mapped.ports.filter(p => criticalPorts.includes(p));
      if (foundCritical.length > 0) {
        await createAlert({
          type: 'port_exposure',
          severity: 'high',
          title: `Critical Ports Exposed on ${mapped.host}`,
          description: `Found critical ports: ${foundCritical.join(', ')}`,
          sourceModule: 'recon',
          target
        });
      }

      toast({
        title: "Scan Complete",
        description: `Found ${mapped.ports.length} open ports on ${api.host}`,
      });
      
      loadHistory();
    } catch (e) {
      console.error(e);
      if (scanId) {
        await completeScan(scanId, { status: 'failed' });
      }
      toast({
        title: "Scan Failed",
        description: e instanceof Error ? e.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setScanning(false);
    }
  };

  const generateReport = async () => {
    if (results.length === 0) {
      toast({ title: "No results to report", variant: "destructive" });
      return;
    }

    const report = await saveReport({
      module: 'recon',
      title: `Reconnaissance Report - ${new Date().toLocaleDateString()}`,
      summary: `Scanned ${results.length} hosts, found ${results.reduce((sum, r) => sum + r.ports.length, 0)} open ports`,
      findings: results,
      severityCounts: {
        critical: 0,
        high: results.filter(r => r.ports.some(p => [22, 23, 3389].includes(p))).length,
        medium: results.filter(r => r.ports.length > 5).length,
        low: results.length
      }
    });

    if (report) {
      toast({ title: "Report Saved" });
      loadHistory();
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />

      <main className="container mx-auto px-6 py-8">
        <Button variant="ghost" onClick={() => navigate("/")} className="mb-6 gap-2">
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Search className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Reconnaissance Module</h1>
          </div>
          <p className="text-muted-foreground">
            Network mapping, asset discovery, and OSINT gathering with MITRE ATT&CK mapping
          </p>
        </div>

        <Tabs defaultValue="scan" className="space-y-4" onValueChange={(v) => v === 'history' && loadHistory()}>
          <TabsList>
            <TabsTrigger value="scan">Scan</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
          </TabsList>

          <TabsContent value="scan">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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

                  <Button onClick={startScan} disabled={scanning} className="w-full bg-cyber-cyan hover:bg-cyber-cyan/80 text-background">
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

                  {results.length > 0 && (
                    <Button variant="outline" onClick={generateReport} className="w-full">
                      <FileText className="h-4 w-4 mr-2" />
                      Save Report
                    </Button>
                  )}

                  <div className="pt-4 border-t border-border/50 space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground font-mono">MITRE</span>
                      <Badge variant="secondary">T1046</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground font-mono">Mode</span>
                      <Badge variant="secondary">Lab Safe</Badge>
                    </div>
                  </div>
                </div>
              </Card>

              <Card className="lg:col-span-2 p-6 bg-card/50 backdrop-blur-sm">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-cyber-purple" />
                  Scan Results
                </h3>

                {results.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-64 text-center">
                    <Globe className="h-16 w-16 text-muted-foreground mb-4 opacity-20" />
                    <p className="text-muted-foreground font-mono">No scans performed yet</p>
                  </div>
                ) : (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-4">
                      {results.map((result) => (
                        <Card key={result.id} className="p-4 bg-background/50 border-cyber-cyan/30">
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className="font-semibold font-mono text-lg">{result.host}</h4>
                              <p className="text-xs text-muted-foreground font-mono">{result.timestamp}</p>
                            </div>
                            <div className="flex gap-2">
                              <Badge variant="outline" className="text-xs">{result.mitre}</Badge>
                              <Badge variant={result.status === "online" ? "default" : "destructive"}>
                                {result.status}
                              </Badge>
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2 mt-1">
                            {result.ports.map((port, idx) => (
                              <Badge key={port} variant="secondary" className="font-mono">
                                {port} • {result.services[idx]}
                              </Badge>
                            ))}
                          </div>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="history">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <History className="h-5 w-5" />
                Scan History
              </h3>
              {history.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">No scan history yet</p>
              ) : (
                <ScrollArea className="h-96">
                  <div className="space-y-2">
                    {history.map((h) => (
                      <div key={h.id} className="flex items-center justify-between p-3 bg-background/50 rounded border border-border/50">
                        <div>
                          <p className="font-medium">{h.scan_type}</p>
                          <p className="text-xs text-muted-foreground">{h.target}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={h.status === 'completed' ? 'default' : 'destructive'}>{h.status}</Badge>
                          <span className="text-xs text-muted-foreground">{h.findings_count || 0} findings</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="reports">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Saved Reports
              </h3>
              {reports.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">No reports saved yet</p>
              ) : (
                <ScrollArea className="h-96">
                  <div className="space-y-2">
                    {reports.map((r) => (
                      <div key={r.id} className="flex items-center justify-between p-3 bg-background/50 rounded border border-border/50">
                        <div>
                          <p className="font-medium">{r.title}</p>
                          <p className="text-xs text-muted-foreground">{r.summary}</p>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {new Date(r.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ReconModule;
