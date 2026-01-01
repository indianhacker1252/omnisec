import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { Globe, Loader2, Shield, AlertTriangle, ArrowLeft, FileText, History } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { ReportGenerator } from "@/components/ReportGenerator";
import { useScanHistory } from "@/hooks/useScanHistory";

interface VulnerabilityFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  url: string;
  method?: string;
  mitre?: string;
  owasp?: string;
}

const WebAppModule = () => {
  const navigate = useNavigate();
  const { logScan, completeScan, createAlert, saveReport, getModuleHistory, getModuleReports } = useScanHistory();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const { toast } = useToast();

  const severityColors = {
    critical: "bg-red-500/10 text-red-500 border-red-500",
    high: "bg-orange-500/10 text-orange-500 border-orange-500",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500",
    low: "bg-blue-500/10 text-blue-500 border-blue-500",
    info: "bg-gray-500/10 text-gray-500 border-gray-500",
  };

  const loadHistory = async () => {
    const h = await getModuleHistory('webapp');
    const r = await getModuleReports('webapp');
    setHistory(h);
    setReports(r);
  };

  const performScan = async () => {
    if (!target.trim()) {
      toast({ title: "Error", description: "Please enter a target URL", variant: "destructive" });
      return;
    }

    setScanning(true);
    setFindings([]);
    toast({ title: "Scanning Started", description: `Initiating scan on ${target}` });

    const scanId = await logScan({
      module: 'webapp',
      scanType: 'Web Application Security Scan',
      target
    });

    try {
      const { data, error } = await supabase.functions.invoke('webapp-scan', {
        body: { target }
      });

      if (error) throw error;

      if (data.success && data.findings) {
        const mappedFindings = data.findings.map((f: any) => ({
          ...f,
          mitre: f.mitre || 'T1190 - Exploit Public-Facing Application',
          owasp: f.owasp || 'A03:2021 - Injection'
        }));
        
        setFindings(mappedFindings);
        
        if (scanId) {
          await completeScan(scanId, {
            status: 'completed',
            findingsCount: mappedFindings.length,
            report: { findings: mappedFindings }
          });
        }

        // Create alerts for critical findings
        const criticalFindings = mappedFindings.filter((f: any) => f.severity === 'critical' || f.severity === 'high');
        for (const finding of criticalFindings.slice(0, 3)) {
          await createAlert({
            type: 'webapp_vulnerability',
            severity: finding.severity as 'critical' | 'high' | 'medium' | 'low',
            title: finding.title,
            description: finding.description,
            sourceModule: 'webapp',
            target
          });
        }

        toast({
          title: "Scan Complete",
          description: `Found ${mappedFindings.length} issues in ${(data.scanTime / 1000).toFixed(2)}s`,
        });
        
        loadHistory();
      }
    } catch (error: any) {
      if (scanId) {
        await completeScan(scanId, { status: 'failed' });
      }
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to complete scan",
        variant: "destructive",
      });
    } finally {
      setScanning(false);
    }
  };

  const generateReport = async () => {
    if (findings.length === 0) return;
    
    await saveReport({
      module: 'webapp',
      title: `Web App Security Report - ${new Date().toLocaleDateString()}`,
      summary: `Scanned ${target}, found ${findings.length} vulnerabilities`,
      findings,
      severityCounts: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      }
    });
    
    toast({ title: "Report Saved" });
    loadHistory();
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <Button variant="outline" onClick={() => navigate('/')} className="mb-6 gap-2">
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>
        
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Globe className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Web & App Analysis</h1>
          </div>
          <p className="text-muted-foreground">
            Automated vulnerability scanning with OWASP Top 10 and MITRE ATT&CK mapping
          </p>
        </div>

        <Tabs defaultValue="scan" className="space-y-4" onValueChange={(v) => v === 'history' && loadHistory()}>
          <TabsList>
            <TabsTrigger value="scan">Scan</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
          </TabsList>

          <TabsContent value="scan">
            <Card className="p-6 mb-6 bg-card/50 backdrop-blur-sm border-cyber-cyan/30">
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Target URL</label>
                  <div className="flex gap-2">
                    <Input
                      type="text"
                      placeholder="https://example.com"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      className="flex-1 font-mono"
                      disabled={scanning}
                    />
                    <Button onClick={performScan} disabled={scanning} className="min-w-[120px]">
                      {scanning ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Shield className="mr-2 h-4 w-4" />
                          Start Scan
                        </>
                      )}
                    </Button>
                  </div>
                </div>

                <div className="flex gap-2 text-xs text-muted-foreground">
                  <AlertTriangle className="h-4 w-4" />
                  <p>Always ensure you have permission to scan the target</p>
                </div>
              </div>
            </Card>

            {findings.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold font-mono">Findings ({findings.length})</h2>
                  <div className="flex items-center gap-3">
                    <div className="flex gap-2">
                      <Badge variant="destructive">
                        {findings.filter(f => f.severity === "critical" || f.severity === "high").length} High Risk
                      </Badge>
                      <Badge variant="secondary">
                        {findings.filter(f => f.severity === "medium" || f.severity === "low").length} Medium/Low
                      </Badge>
                    </div>
                    <Button variant="outline" onClick={generateReport}>
                      <FileText className="h-4 w-4 mr-2" />
                      Save Report
                    </Button>
                    <ReportGenerator
                      data={{
                        target,
                        scanType: "Web Application Security Scan",
                        timestamp: new Date().toISOString(),
                        findings,
                        summary: {
                          total: findings.length,
                          critical: findings.filter(f => f.severity === "critical").length,
                          high: findings.filter(f => f.severity === "high").length,
                          medium: findings.filter(f => f.severity === "medium").length,
                          low: findings.filter(f => f.severity === "low").length,
                        }
                      }}
                    />
                  </div>
                </div>

                <div className="grid gap-4">
                  {findings.map((finding, idx) => (
                    <Card key={idx} className={`p-4 border ${severityColors[finding.severity]}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-5 w-5" />
                          <h3 className="font-semibold">{finding.title}</h3>
                        </div>
                        <div className="flex gap-2">
                          {finding.mitre && <Badge variant="outline" className="text-xs">{finding.mitre}</Badge>}
                          <Badge variant="outline" className="uppercase text-xs">{finding.severity}</Badge>
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                      <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground">
                        <span>{finding.method}</span>
                        <span className="truncate">{finding.url}</span>
                        {finding.owasp && <span>{finding.owasp}</span>}
                      </div>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {!scanning && findings.length === 0 && (
              <Card className="p-12 text-center border-dashed">
                <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">
                  Enter a target URL and start scanning to discover vulnerabilities
                </p>
              </Card>
            )}
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

export default WebAppModule;
