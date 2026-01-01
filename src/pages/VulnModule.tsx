import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bug, Activity, AlertTriangle, ArrowLeft, FileText, History } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useScanHistory } from "@/hooks/useScanHistory";

interface Vulnerability {
  id: string;
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  cvss: number;
  timestamp: string;
  mitre?: string;
  owasp?: string;
}

const VulnModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { logScan, completeScan, createAlert, saveReport, getModuleHistory, getModuleReports } = useScanHistory();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);

  const loadHistory = async () => {
    const h = await getModuleHistory('vuln');
    const r = await getModuleReports('vuln');
    setHistory(h);
    setReports(r);
  };

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

    const scanId = await logScan({
      module: 'vuln',
      scanType: 'Vulnerability Intelligence',
      target
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
        mitre: v.mitre || 'T1190 - Exploit Public-Facing Application',
        owasp: v.owasp || 'A06:2021 - Vulnerable and Outdated Components'
      }));
      
      setVulnerabilities((prev) => [...mapped, ...prev]);
      
      if (scanId) {
        await completeScan(scanId, {
          status: 'completed',
          findingsCount: mapped.length,
          report: { vulnerabilities: mapped }
        });
      }

      // Create alerts for critical/high vulns
      const critical = mapped.filter(v => v.severity === 'critical' || v.severity === 'high');
      for (const vuln of critical.slice(0, 3)) {
        await createAlert({
          type: 'vulnerability',
          severity: vuln.severity as 'critical' | 'high' | 'medium' | 'low',
          title: vuln.title,
          description: `${vuln.cve} - CVSS: ${vuln.cvss}`,
          sourceModule: 'vuln',
          target
        });
      }

      toast({ title: "Scan Complete", description: `Found ${mapped.length} vulnerabilities` });
      loadHistory();
    } catch (e) {
      console.error(e);
      if (scanId) {
        await completeScan(scanId, { status: 'failed' });
      }
      toast({ title: "Scan Failed", description: e instanceof Error ? e.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setScanning(false);
    }
  };

  const generateReport = async () => {
    if (vulnerabilities.length === 0) return;
    
    await saveReport({
      module: 'vuln',
      title: `Vulnerability Report - ${new Date().toLocaleDateString()}`,
      summary: `Found ${vulnerabilities.length} vulnerabilities`,
      findings: vulnerabilities,
      severityCounts: {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
      }
    });
    
    toast({ title: "Report Saved" });
    loadHistory();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-500 border-red-500";
      case "high": return "text-orange-500 border-orange-500";
      case "medium": return "text-yellow-500 border-yellow-500";
      case "low": return "text-blue-500 border-blue-500";
      default: return "";
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
            <Bug className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">Vulnerability Intelligence</h1>
          </div>
          <p className="text-muted-foreground">
            CVE correlation, MITRE ATT&CK mapping, and exploit database integration
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

                  <Button onClick={startScan} disabled={scanning} className="w-full bg-cyber-purple hover:bg-cyber-purple/80 text-background">
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

                  {vulnerabilities.length > 0 && (
                    <Button variant="outline" onClick={generateReport} className="w-full">
                      <FileText className="h-4 w-4 mr-2" />
                      Save Report
                    </Button>
                  )}

                  <div className="pt-4 border-t border-border/50">
                    <h4 className="text-sm font-semibold mb-3 font-mono">Statistics</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-red-500 font-mono">Critical</span>
                        <span className="font-mono">{vulnerabilities.filter((v) => v.severity === "critical").length}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-orange-500 font-mono">High</span>
                        <span className="font-mono">{vulnerabilities.filter((v) => v.severity === "high").length}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-yellow-500 font-mono">Medium</span>
                        <span className="font-mono">{vulnerabilities.filter((v) => v.severity === "medium").length}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-blue-500 font-mono">Low</span>
                        <span className="font-mono">{vulnerabilities.filter((v) => v.severity === "low").length}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>

              <Card className="lg:col-span-2 p-6 bg-card/50 backdrop-blur-sm">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-orange-500" />
                  Detected Vulnerabilities
                </h3>

                {vulnerabilities.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-64 text-center">
                    <Bug className="h-16 w-16 text-muted-foreground mb-4 opacity-20" />
                    <p className="text-muted-foreground font-mono">No vulnerabilities found yet</p>
                  </div>
                ) : (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-4">
                      {vulnerabilities.map((vuln) => (
                        <Card key={vuln.id} className={`p-4 bg-background/50 border ${getSeverityColor(vuln.severity)}`}>
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1 flex-wrap">
                                <Badge variant="secondary" className="font-mono text-xs">{vuln.cve}</Badge>
                                <Badge variant={vuln.severity === "critical" ? "destructive" : "secondary"} className="font-mono text-xs">
                                  {vuln.severity.toUpperCase()}
                                </Badge>
                                {vuln.mitre && <Badge variant="outline" className="text-xs">{vuln.mitre}</Badge>}
                              </div>
                              <h4 className="font-semibold text-lg mb-1">{vuln.title}</h4>
                              <p className="text-sm text-muted-foreground mb-2">{vuln.description}</p>
                              <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                                <span>CVSS: {vuln.cvss}</span>
                                <span>•</span>
                                <span>{vuln.timestamp}</span>
                                {vuln.owasp && <><span>•</span><span>{vuln.owasp}</span></>}
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
                        <span className="text-xs text-muted-foreground">{new Date(r.created_at).toLocaleDateString()}</span>
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

export default VulnModule;
