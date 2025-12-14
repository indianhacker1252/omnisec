/**
 * OmniSec™ Cloud Security Module
 * © HARSH MALIK. All Rights Reserved.
 * Advanced Cloud Security Assessment
 */

import { useState, useEffect } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Cloud, Activity, AlertTriangle, ArrowLeft, Shield, 
  Server, Database, Lock, FileWarning, CheckCircle, History
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useScanHistory } from "@/hooks/useScanHistory";
import { ReportGenerator } from "@/components/ReportGenerator";

interface CloudFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  resource: string;
  provider: string;
  mitreAttack?: string;
  remediation: string;
}

const CloudSecurityModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { logScan, completeScan, createAlert, saveReport, getModuleHistory, getModuleReports } = useScanHistory();
  
  const [provider, setProvider] = useState("aws");
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<CloudFinding[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState("scan");

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    const hist = await getModuleHistory('cloud-security');
    const reps = await getModuleReports('cloud-security');
    setHistory(hist);
    setReports(reps);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/10 text-red-500 border-red-500";
      case "high": return "bg-orange-500/10 text-orange-500 border-orange-500";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500";
      case "low": return "bg-blue-500/10 text-blue-500 border-blue-500";
      default: return "bg-gray-500/10 text-gray-500 border-gray-500";
    }
  };

  const startScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Invalid Target",
        description: "Please enter a valid cloud resource identifier",
        variant: "destructive",
      });
      return;
    }

    setScanning(true);
    setFindings([]);
    const scanId = await logScan({
      module: 'cloud-security',
      scanType: `${provider.toUpperCase()} Security Scan`,
      target
    });

    toast({
      title: "Cloud Security Scan Started",
      description: `Analyzing ${provider.toUpperCase()} environment: ${target}`,
    });

    try {
      const { data, error } = await supabase.functions.invoke('cloud-security', {
        body: { provider, target }
      });
      
      if (error) throw error;

      const scanFindings: CloudFinding[] = data.findings || [];
      setFindings(scanFindings);

      // Create alerts for critical/high findings
      for (const finding of scanFindings.filter(f => f.severity === 'critical' || f.severity === 'high')) {
        await createAlert({
          type: 'cloud_misconfiguration',
          severity: finding.severity as 'critical' | 'high' | 'medium' | 'low',
          title: finding.title,
          description: finding.description,
          sourceModule: 'cloud-security',
          target
        });
      }

      // Complete scan and save report
      if (scanId) {
        await completeScan(scanId, {
          status: 'completed',
          findingsCount: scanFindings.length,
          report: data
        });

        await saveReport({
          scanId,
          module: 'cloud-security',
          title: `${provider.toUpperCase()} Security Assessment - ${target}`,
          summary: `Found ${scanFindings.length} security issues`,
          findings: scanFindings,
          severityCounts: {
            critical: scanFindings.filter(f => f.severity === 'critical').length,
            high: scanFindings.filter(f => f.severity === 'high').length,
            medium: scanFindings.filter(f => f.severity === 'medium').length,
            low: scanFindings.filter(f => f.severity === 'low').length,
          }
        });
      }

      toast({
        title: "Scan Complete",
        description: `Found ${scanFindings.length} cloud security issues`,
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
            <Cloud className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Cloud Security</h1>
          </div>
          <p className="text-muted-foreground">
            AWS, Azure, GCP misconfiguration detection & compliance assessment
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-6">
            <TabsTrigger value="scan" className="gap-2">
              <Shield className="h-4 w-4" />
              Scan
            </TabsTrigger>
            <TabsTrigger value="history" className="gap-2">
              <History className="h-4 w-4" />
              History
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scan">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="lg:col-span-1 p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Activity className="h-5 w-5 text-cyber-cyan" />
                  Scan Configuration
                </h3>

                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-mono mb-2 block">Cloud Provider</label>
                    <Select value={provider} onValueChange={setProvider}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                        <SelectItem value="azure">Microsoft Azure</SelectItem>
                        <SelectItem value="gcp">Google Cloud Platform</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <label className="text-sm font-mono mb-2 block">Target (Account/Project/Resource)</label>
                    <Input
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="account-id or project-name"
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
                        <Cloud className="h-4 w-4 mr-2" />
                        Start Cloud Scan
                      </>
                    )}
                  </Button>

                  <div className="pt-4 border-t border-border/50 space-y-2">
                    <h4 className="text-sm font-semibold font-mono">Checks Include:</h4>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      <li className="flex items-center gap-2">
                        <Lock className="h-3 w-3" /> IAM Misconfigurations
                      </li>
                      <li className="flex items-center gap-2">
                        <Database className="h-3 w-3" /> S3/Blob Public Access
                      </li>
                      <li className="flex items-center gap-2">
                        <Server className="h-3 w-3" /> EC2/VM Security Groups
                      </li>
                      <li className="flex items-center gap-2">
                        <Shield className="h-3 w-3" /> Encryption at Rest
                      </li>
                      <li className="flex items-center gap-2">
                        <FileWarning className="h-3 w-3" /> Logging & Monitoring
                      </li>
                    </ul>
                  </div>
                </div>
              </Card>

              <Card className="lg:col-span-2 p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-warning" />
                    Cloud Security Findings
                  </h3>
                  {findings.length > 0 && (
                    <ReportGenerator
                      data={{
                        target,
                        scanType: `${provider.toUpperCase()} Cloud Security Scan`,
                        timestamp: new Date().toISOString(),
                        findings,
                        summary: {
                          total: findings.length,
                          critical: findings.filter(f => f.severity === 'critical').length,
                          high: findings.filter(f => f.severity === 'high').length,
                          medium: findings.filter(f => f.severity === 'medium').length,
                          low: findings.filter(f => f.severity === 'low').length,
                        }
                      }}
                    />
                  )}
                </div>

                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-64 text-center">
                    <Cloud className="h-16 w-16 text-muted-foreground mb-4 opacity-20" />
                    <p className="text-muted-foreground font-mono">No findings yet</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      Configure and start a cloud security scan
                    </p>
                  </div>
                ) : (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-4">
                      {findings.map((finding) => (
                        <Card key={finding.id} className={`p-4 bg-background/50 border ${getSeverityColor(finding.severity)}`}>
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant="secondary" className="font-mono text-xs">
                                  {finding.provider.toUpperCase()}
                                </Badge>
                                <Badge variant={finding.severity === 'critical' ? 'destructive' : 'secondary'} className="font-mono text-xs">
                                  {finding.severity.toUpperCase()}
                                </Badge>
                                {finding.mitreAttack && (
                                  <Badge variant="outline" className="font-mono text-xs">
                                    {finding.mitreAttack}
                                  </Badge>
                                )}
                              </div>
                              <h4 className="font-semibold text-lg mb-1">{finding.title}</h4>
                              <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                              <div className="text-xs font-mono text-muted-foreground mb-2">
                                Resource: {finding.resource}
                              </div>
                              <div className="bg-background/50 p-2 rounded text-xs">
                                <span className="font-semibold text-cyber-cyan">Remediation:</span> {finding.remediation}
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
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <History className="h-5 w-5 text-cyber-cyan" />
                  Scan History
                </h3>
                <ScrollArea className="h-[400px]">
                  {history.length === 0 ? (
                    <p className="text-muted-foreground text-center py-8">No scan history</p>
                  ) : (
                    <div className="space-y-3">
                      {history.map((item) => (
                        <div key={item.id} className="p-3 bg-background/50 rounded border border-border/50">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-sm">{item.scan_type}</span>
                            <Badge variant={item.status === 'completed' ? 'default' : 'secondary'}>
                              {item.status}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground">{item.target}</p>
                          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                            <span>{new Date(item.created_at).toLocaleString()}</span>
                            {item.findings_count > 0 && (
                              <Badge variant="outline">{item.findings_count} findings</Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </Card>

              <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <FileWarning className="h-5 w-5 text-cyber-purple" />
                  Generated Reports
                </h3>
                <ScrollArea className="h-[400px]">
                  {reports.length === 0 ? (
                    <p className="text-muted-foreground text-center py-8">No reports generated</p>
                  ) : (
                    <div className="space-y-3">
                      {reports.map((report) => (
                        <div key={report.id} className="p-3 bg-background/50 rounded border border-border/50">
                          <h4 className="font-semibold text-sm mb-1">{report.title}</h4>
                          <p className="text-xs text-muted-foreground mb-2">{report.summary}</p>
                          <div className="flex items-center gap-2 text-xs">
                            {report.severity_counts && (
                              <>
                                <Badge variant="destructive">{report.severity_counts.critical || 0} Critical</Badge>
                                <Badge variant="secondary">{report.severity_counts.high || 0} High</Badge>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default CloudSecurityModule;
