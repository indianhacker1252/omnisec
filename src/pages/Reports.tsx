import { useState, useEffect } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { 
  ArrowLeft, FileText, Download, Search, Filter, Calendar, 
  AlertTriangle, Shield, Globe, Cloud, Key, Network, Bug, 
  Sword, Zap, Eye, RefreshCw, Trash2, ChevronRight
} from "lucide-react";

interface Report {
  id: string;
  created_at: string;
  module: string;
  title: string;
  summary: string | null;
  findings: any;
  recommendations: any;
  severity_counts: any;
  scan_id: string | null;
}

interface ScanHistory {
  id: string;
  created_at: string;
  module: string;
  scan_type: string;
  target: string | null;
  status: string;
  findings_count: number | null;
  duration_ms: number | null;
  report: any;
}

const moduleIcons: Record<string, any> = {
  recon: Search,
  webapp: Globe,
  vuln: Bug,
  api: Network,
  cloud: Cloud,
  iam: Key,
  red_team: Sword,
  full_audit: Shield,
  autonomous_attack: Zap,
  wireless: Network,
  forensics: FileText,
  reverse: FileText,
};

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/50",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/50",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/50",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/50",
};

const Reports = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [reports, setReports] = useState<Report[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [moduleFilter, setModuleFilter] = useState("all");
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [reportsRes, historyRes] = await Promise.all([
        supabase.from('security_reports').select('*').order('created_at', { ascending: false }).limit(100),
        supabase.from('scan_history').select('*').order('created_at', { ascending: false }).limit(200)
      ]);

      if (reportsRes.data) setReports(reportsRes.data);
      if (historyRes.data) setScanHistory(historyRes.data);
    } catch (error) {
      console.error('Error fetching data:', error);
      toast({ title: "Error", description: "Failed to load reports", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const filteredReports = reports.filter(r => {
    const matchesSearch = !searchQuery || 
      r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.module.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.summary && r.summary.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesModule = moduleFilter === "all" || r.module === moduleFilter;
    return matchesSearch && matchesModule;
  });

  const filteredHistory = scanHistory.filter(s => {
    const matchesSearch = !searchQuery || 
      s.scan_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.module.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (s.target && s.target.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesModule = moduleFilter === "all" || s.module === moduleFilter;
    return matchesSearch && matchesModule;
  });

  const exportReport = (report: Report) => {
    const content = {
      title: report.title,
      module: report.module,
      created_at: report.created_at,
      summary: report.summary,
      severity_counts: report.severity_counts,
      findings: report.findings,
      recommendations: report.recommendations
    };
    
    const blob = new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.title.replace(/\s+/g, '_')}_${new Date(report.created_at).toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "Exported", description: "Report downloaded successfully" });
  };

  const exportAllReports = () => {
    const content = {
      exported_at: new Date().toISOString(),
      total_reports: filteredReports.length,
      reports: filteredReports.map(r => ({
        title: r.title,
        module: r.module,
        created_at: r.created_at,
        summary: r.summary,
        severity_counts: r.severity_counts,
        findings: r.findings
      }))
    };
    
    const blob = new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `omnisec_reports_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "Exported", description: `${filteredReports.length} reports downloaded` });
  };

  const uniqueModules = Array.from(new Set([...reports.map(r => r.module), ...scanHistory.map(s => s.module)]));

  const totalFindings = reports.reduce((sum, r) => {
    const counts = r.severity_counts || {};
    return sum + (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0);
  }, 0);

  const criticalCount = reports.reduce((sum, r) => sum + (r.severity_counts?.critical || 0), 0);
  const highCount = reports.reduce((sum, r) => sum + (r.severity_counts?.high || 0), 0);

  const getModuleIcon = (module: string) => {
    const Icon = moduleIcons[module] || FileText;
    return <Icon className="h-4 w-4" />;
  };

  const formatDuration = (ms: number | null) => {
    if (!ms) return 'N/A';
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };

  const renderFindingsDetail = (findings: any) => {
    if (!findings) return <p className="text-muted-foreground">No findings data</p>;
    
    if (typeof findings === 'object') {
      return (
        <div className="space-y-4">
          {Object.entries(findings).map(([key, value]: [string, any]) => (
            <div key={key} className="border border-border/50 rounded-lg p-4">
              <h4 className="font-semibold capitalize mb-2">{key.replace(/_/g, ' ')}</h4>
              {Array.isArray(value) ? (
                <div className="space-y-2">
                  {value.slice(0, 10).map((item: any, i: number) => (
                    <div key={i} className="text-sm p-2 bg-muted/30 rounded">
                      {typeof item === 'object' ? (
                        <div>
                          {item.title && <span className="font-medium">{item.title}</span>}
                          {item.severity && <Badge className={`ml-2 ${severityColors[item.severity] || ''}`}>{item.severity}</Badge>}
                          {item.description && <p className="text-xs text-muted-foreground mt-1">{item.description}</p>}
                          {item.cve && <span className="text-xs text-cyber-cyan">{item.cve}</span>}
                        </div>
                      ) : (
                        <span>{String(item)}</span>
                      )}
                    </div>
                  ))}
                  {value.length > 10 && (
                    <p className="text-xs text-muted-foreground">...and {value.length - 10} more</p>
                  )}
                </div>
              ) : typeof value === 'object' ? (
                <pre className="text-xs bg-muted/30 p-2 rounded overflow-auto max-h-40">
                  {JSON.stringify(value, null, 2)}
                </pre>
              ) : (
                <p className="text-sm">{String(value)}</p>
              )}
            </div>
          ))}
        </div>
      );
    }
    
    return <pre className="text-xs">{JSON.stringify(findings, null, 2)}</pre>;
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <FileText className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">Security Reports</h1>
          </div>
          <p className="text-muted-foreground">
            Centralized view of all security scan reports and findings
          </p>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <Card className="p-4 bg-card/50 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <FileText className="h-8 w-8 text-cyber-cyan" />
              <div>
                <p className="text-2xl font-bold">{reports.length}</p>
                <p className="text-xs text-muted-foreground">Total Reports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4 bg-card/50 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <Search className="h-8 w-8 text-cyber-purple" />
              <div>
                <p className="text-2xl font-bold">{scanHistory.length}</p>
                <p className="text-xs text-muted-foreground">Total Scans</p>
              </div>
            </div>
          </Card>
          <Card className="p-4 bg-card/50 backdrop-blur-sm border-red-500/30">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-red-400" />
              <div>
                <p className="text-2xl font-bold">{criticalCount}</p>
                <p className="text-xs text-muted-foreground">Critical Issues</p>
              </div>
            </div>
          </Card>
          <Card className="p-4 bg-card/50 backdrop-blur-sm border-orange-500/30">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-orange-400" />
              <div>
                <p className="text-2xl font-bold">{highCount}</p>
                <p className="text-xs text-muted-foreground">High Severity</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Filters */}
        <Card className="p-4 mb-6 bg-card/50 backdrop-blur-sm">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search reports, targets, modules..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={moduleFilter} onValueChange={setModuleFilter}>
              <SelectTrigger className="w-[180px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Filter by module" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Modules</SelectItem>
                {uniqueModules.map(m => (
                  <SelectItem key={m} value={m}>{m.replace(/_/g, ' ').toUpperCase()}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={fetchData} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button onClick={exportAllReports} disabled={filteredReports.length === 0}>
              <Download className="h-4 w-4 mr-2" />
              Export All
            </Button>
          </div>
        </Card>

        <Tabs defaultValue="reports" className="space-y-6">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="reports">
              <FileText className="h-4 w-4 mr-2" />
              Reports ({filteredReports.length})
            </TabsTrigger>
            <TabsTrigger value="history">
              <Calendar className="h-4 w-4 mr-2" />
              Scan History ({filteredHistory.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="reports">
            <div className="space-y-4">
              {loading ? (
                <Card className="p-8 text-center">
                  <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2 text-muted-foreground" />
                  <p className="text-muted-foreground">Loading reports...</p>
                </Card>
              ) : filteredReports.length === 0 ? (
                <Card className="p-8 text-center">
                  <FileText className="h-12 w-12 mx-auto mb-2 text-muted-foreground" />
                  <p className="text-muted-foreground">No reports found</p>
                  <p className="text-xs text-muted-foreground mt-1">Run scans using the AI Assistant to generate reports</p>
                </Card>
              ) : (
                filteredReports.map((report) => (
                  <Card key={report.id} className="p-4 hover:bg-muted/30 transition-colors cursor-pointer" onClick={() => setSelectedReport(report)}>
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-cyber-purple/20">
                          {getModuleIcon(report.module)}
                        </div>
                        <div>
                          <h3 className="font-semibold">{report.title}</h3>
                          <p className="text-sm text-muted-foreground">{report.summary || 'No summary'}</p>
                          <div className="flex items-center gap-2 mt-2">
                            <Badge variant="outline">{report.module.replace(/_/g, ' ')}</Badge>
                            <span className="text-xs text-muted-foreground">
                              {new Date(report.created_at).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {report.severity_counts && (
                          <div className="flex gap-1">
                            {report.severity_counts.critical > 0 && (
                              <Badge className={severityColors.critical}>{report.severity_counts.critical} Crit</Badge>
                            )}
                            {report.severity_counts.high > 0 && (
                              <Badge className={severityColors.high}>{report.severity_counts.high} High</Badge>
                            )}
                          </div>
                        )}
                        <Button variant="ghost" size="icon" onClick={(e) => { e.stopPropagation(); exportReport(report); }}>
                          <Download className="h-4 w-4" />
                        </Button>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </div>
                  </Card>
                ))
              )}
            </div>
          </TabsContent>

          <TabsContent value="history">
            <div className="space-y-2">
              {loading ? (
                <Card className="p-8 text-center">
                  <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2 text-muted-foreground" />
                  <p className="text-muted-foreground">Loading scan history...</p>
                </Card>
              ) : filteredHistory.length === 0 ? (
                <Card className="p-8 text-center">
                  <Calendar className="h-12 w-12 mx-auto mb-2 text-muted-foreground" />
                  <p className="text-muted-foreground">No scan history found</p>
                </Card>
              ) : (
                filteredHistory.map((scan) => (
                  <Card key={scan.id} className="p-3 hover:bg-muted/30 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${scan.status === 'completed' ? 'bg-green-500/20' : scan.status === 'failed' ? 'bg-red-500/20' : 'bg-yellow-500/20'}`}>
                          {getModuleIcon(scan.module)}
                        </div>
                        <div>
                          <p className="font-medium text-sm">{scan.scan_type}</p>
                          <p className="text-xs text-muted-foreground">
                            {scan.target || 'No target'} • {new Date(scan.created_at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant={scan.status === 'completed' ? 'default' : scan.status === 'failed' ? 'destructive' : 'secondary'}>
                          {scan.status}
                        </Badge>
                        {scan.findings_count !== null && (
                          <span className="text-sm font-mono">{scan.findings_count} findings</span>
                        )}
                        <span className="text-xs text-muted-foreground">{formatDuration(scan.duration_ms)}</span>
                      </div>
                    </div>
                  </Card>
                ))
              )}
            </div>
          </TabsContent>
        </Tabs>

        {/* Report Detail Dialog */}
        <Dialog open={!!selectedReport} onOpenChange={() => setSelectedReport(null)}>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                {selectedReport && getModuleIcon(selectedReport.module)}
                {selectedReport?.title}
              </DialogTitle>
            </DialogHeader>
            <ScrollArea className="flex-1 pr-4">
              {selectedReport && (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground">Module</p>
                      <Badge variant="outline">{selectedReport.module.replace(/_/g, ' ')}</Badge>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Created</p>
                      <p className="text-sm">{new Date(selectedReport.created_at).toLocaleString()}</p>
                    </div>
                  </div>

                  {selectedReport.summary && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Summary</p>
                      <p className="text-sm">{selectedReport.summary}</p>
                    </div>
                  )}

                  {selectedReport.severity_counts && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Severity Breakdown</p>
                      <div className="flex gap-2">
                        {Object.entries(selectedReport.severity_counts).map(([sev, count]) => (
                          <Badge key={sev} className={severityColors[sev] || ''}>
                            {sev}: {count as number}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Findings Detail</p>
                    {renderFindingsDetail(selectedReport.findings)}
                  </div>

                  <div className="flex gap-2 pt-4 border-t">
                    <Button onClick={() => exportReport(selectedReport)}>
                      <Download className="h-4 w-4 mr-2" />
                      Export Report
                    </Button>
                  </div>
                </div>
              )}
            </ScrollArea>
          </DialogContent>
        </Dialog>
      </main>
    </div>
  );
};

export default Reports;
