import { useState, useEffect } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { PDFReportGenerator } from "@/components/PDFReportGenerator";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { FileText, Download, RefreshCw, Eye, Calendar, Target } from "lucide-react";

interface ReportData {
  id: string;
  created_at: string;
  module: string;
  title: string;
  summary: string | null;
  findings: any;
  recommendations: any;
  severity_counts: any;
}

const PDFReportsPage = () => {
  const { toast } = useToast();
  const [reports, setReports] = useState<ReportData[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('security_reports')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setReports(data || []);
    } catch (error) {
      console.error('Error fetching reports:', error);
      toast({ title: "Error", description: "Failed to load reports", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const extractFindings = (report: ReportData): any[] => {
    if (!report.findings) return [];
    
    const findings: any[] = [];
    
    const extractFromObject = (obj: any, source: string = '') => {
      if (Array.isArray(obj)) {
        obj.forEach(item => {
          if (item && typeof item === 'object') {
            findings.push({
              ...item,
              endpoint: item.endpoint || item.url || item.target || source,
              title: item.title || item.name || 'Finding',
              severity: item.severity || 'info',
              description: item.description || item.desc || JSON.stringify(item).slice(0, 200)
            });
          }
        });
      } else if (typeof obj === 'object' && obj !== null) {
        Object.entries(obj).forEach(([key, value]) => {
          if (Array.isArray(value)) {
            extractFromObject(value, key);
          } else if (typeof value === 'object' && value !== null) {
            extractFromObject(value, key);
          }
        });
      }
    };

    extractFromObject(report.findings);
    return findings;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg">
              <FileText className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">PDF Report Generator</h1>
              <p className="text-muted-foreground">Generate professional security assessment reports</p>
            </div>
          </div>
          <Button onClick={fetchReports} variant="outline" className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Report List */}
          <Card className="p-4">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Eye className="h-5 w-5" />
              Available Reports
            </h2>
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">Loading reports...</div>
            ) : reports.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No reports available. Run scans to generate reports.
              </div>
            ) : (
              <ScrollArea className="h-[600px]">
                <div className="space-y-3">
                  {reports.map((report) => {
                    const severityCounts = report.severity_counts || {};
                    return (
                      <div
                        key={report.id}
                        onClick={() => setSelectedReport(report)}
                        className={`p-4 rounded-lg border cursor-pointer transition-all hover:border-primary/50 ${
                          selectedReport?.id === report.id ? 'border-primary bg-primary/5' : 'border-border'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h3 className="font-medium">{report.title}</h3>
                            <p className="text-sm text-muted-foreground flex items-center gap-2 mt-1">
                              <Target className="h-3 w-3" />
                              {report.module.replace(/_/g, ' ').toUpperCase()}
                            </p>
                          </div>
                          <Badge variant="outline" className="text-xs">
                            <Calendar className="h-3 w-3 mr-1" />
                            {new Date(report.created_at).toLocaleDateString()}
                          </Badge>
                        </div>
                        
                        <div className="flex gap-2 mt-3">
                          {severityCounts.critical > 0 && (
                            <Badge className={getSeverityColor('critical')}>
                              {severityCounts.critical} Critical
                            </Badge>
                          )}
                          {severityCounts.high > 0 && (
                            <Badge className={getSeverityColor('high')}>
                              {severityCounts.high} High
                            </Badge>
                          )}
                          {severityCounts.medium > 0 && (
                            <Badge className={getSeverityColor('medium')}>
                              {severityCounts.medium} Medium
                            </Badge>
                          )}
                          {severityCounts.low > 0 && (
                            <Badge className={getSeverityColor('low')}>
                              {severityCounts.low} Low
                            </Badge>
                          )}
                        </div>

                        {report.summary && (
                          <p className="text-sm text-muted-foreground mt-2 line-clamp-2">
                            {report.summary}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            )}
          </Card>

          {/* PDF Generator */}
          <div>
            {selectedReport ? (
              <PDFReportGenerator
                data={{
                  title: selectedReport.title,
                  target: selectedReport.module,
                  date: selectedReport.created_at,
                  executiveSummary: selectedReport.summary || undefined,
                  findings: extractFindings(selectedReport),
                  severityCounts: selectedReport.severity_counts || {
                    critical: 0, high: 0, medium: 0, low: 0
                  },
                  recommendations: selectedReport.recommendations
                }}
              />
            ) : (
              <Card className="p-8 h-full flex items-center justify-center">
                <div className="text-center text-muted-foreground">
                  <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select a report from the list to generate PDF</p>
                </div>
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default PDFReportsPage;
