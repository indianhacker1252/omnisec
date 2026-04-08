/**
 * ScanHistoryViewer — View detailed findings from any past scan
 */
import { useState, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { FindingDetailModal } from "@/components/FindingDetailModal";
import { FindingVerificationPanel } from "@/components/FindingVerificationPanel";
import {
  History, ChevronRight, Bug, Globe, Shield, Clock, Target,
  ChevronDown, ChevronUp, ExternalLink, Eye
} from "lucide-react";

interface ScanRecord {
  id: string;
  target: string;
  status: string;
  findings_count: number;
  duration_ms: number;
  created_at: string;
  scan_type: string;
  report: any;
}

interface Finding {
  id: string;
  severity: string;
  title: string;
  description: string;
  endpoint: string;
  subdomain?: string;
  method?: string;
  payload?: string;
  evidence?: string;
  evidence2?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  owasp?: string;
  mitre?: string[];
  confidence: number;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
  dualConfirmed?: boolean;
  retryCount?: number;
  category?: string;
}

export const ScanHistoryViewer = () => {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [verifyFinding, setVerifyFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  const loadScans = useCallback(async () => {
    setLoading(true);
    const { data } = await supabase
      .from("scan_history")
      .select("id, target, status, findings_count, duration_ms, created_at, scan_type, report")
      .eq("module", "autonomous_vapt")
      .order("created_at", { ascending: false })
      .limit(50);
    setScans(data || []);
    setLoading(false);
  }, []);

  useEffect(() => { loadScans(); }, [loadScans]);

  const getFindings = (scan: ScanRecord): Finding[] => {
    const report = scan.report as any;
    return Array.isArray(report?.findings) ? report.findings : [];
  };

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case "critical": return "bg-destructive/20 text-destructive border-destructive/50";
      case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/50";
      case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
      case "low": return "bg-primary/20 text-primary border-primary/50";
      default: return "bg-muted text-muted-foreground border-border";
    }
  };

  if (loading) return <div className="text-muted-foreground text-sm animate-pulse p-4">Loading scan history...</div>;

  return (
    <div className="space-y-4">
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onConfirm={() => setSelectedFinding(null)}
          onFalsePositive={() => setSelectedFinding(null)}
        />
      )}
      {verifyFinding && (
        <FindingVerificationPanel
          finding={verifyFinding}
          onClose={() => setVerifyFinding(null)}
          onStatusChange={() => setVerifyFinding(null)}
        />
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <History className="h-5 w-5 text-primary" />
          <h3 className="font-semibold text-lg">Scan History</h3>
          <Badge variant="outline" className="text-xs">{scans.length} scans</Badge>
        </div>
        <Button variant="outline" size="sm" onClick={loadScans} className="text-xs gap-1">
          <ExternalLink className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {scans.length === 0 && (
        <Card className="p-8 text-center text-muted-foreground">
          <Bug className="h-10 w-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No scans yet. Start an Autonomous VAPT scan to see results here.</p>
        </Card>
      )}

      <div className="space-y-2">
        {scans.map(scan => {
          const findings = getFindings(scan);
          const isExpanded = expandedScanId === scan.id;
          const sevCounts = {
            critical: findings.filter(f => f.severity === "critical").length,
            high: findings.filter(f => f.severity === "high").length,
            medium: findings.filter(f => f.severity === "medium").length,
            low: findings.filter(f => f.severity === "low").length,
          };
          const date = new Date(scan.created_at);

          return (
            <Card key={scan.id} className={`border-border/50 transition-all ${isExpanded ? "border-primary/30" : "hover:border-primary/20"}`}>
              {/* Header row */}
              <div
                className="p-4 cursor-pointer flex items-center gap-3"
                onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
              >
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  {isExpanded ? <ChevronDown className="h-4 w-4 text-primary shrink-0" /> : <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />}
                  <Target className="h-4 w-4 text-primary shrink-0" />
                  <span className="font-mono text-sm truncate">{scan.target?.replace(/^https?:\/\//, "")}</span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Badge variant={scan.status === "completed" ? "default" : scan.status === "running" ? "secondary" : "destructive"} className="text-[10px]">
                    {scan.status}
                  </Badge>
                  {sevCounts.critical > 0 && <Badge className="text-[10px] bg-destructive/20 text-destructive border-destructive/50">{sevCounts.critical}C</Badge>}
                  {sevCounts.high > 0 && <Badge className="text-[10px] bg-orange-500/20 text-orange-400 border-orange-500/50">{sevCounts.high}H</Badge>}
                  {sevCounts.medium > 0 && <Badge className="text-[10px] bg-yellow-500/20 text-yellow-400 border-yellow-500/50">{sevCounts.medium}M</Badge>}
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Bug className="h-3 w-3" />{scan.findings_count || findings.length}
                  </span>
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Clock className="h-3 w-3" />{Math.round((scan.duration_ms || 0) / 1000)}s
                  </span>
                  <span className="text-[10px] text-muted-foreground">{date.toLocaleDateString()} {date.toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Expanded findings */}
              {isExpanded && (
                <div className="border-t border-border/30 p-4">
                  {findings.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-4">No findings in this scan.</p>
                  ) : (
                    <ScrollArea className="max-h-[500px]">
                      <div className="space-y-2 pr-2">
                        {findings.filter(f => !f.falsePositive).map((finding, i) => (
                          <Card
                            key={finding.id || i}
                            className="p-3 cursor-pointer hover:border-primary/30 transition-all border-border/30"
                            onClick={() => setSelectedFinding(finding)}
                          >
                            <div className="flex items-start gap-2">
                              <Badge className={`text-[10px] border shrink-0 ${getSeverityStyle(finding.severity)}`}>
                                {finding.severity?.toUpperCase()}
                              </Badge>
                              {finding.dualConfirmed && (
                                <Badge variant="outline" className="text-[10px] border-green-500/50 text-green-400 shrink-0">✓ Confirmed</Badge>
                              )}
                              <div className="min-w-0 flex-1">
                                <p className="text-sm font-medium leading-tight">{finding.title}</p>
                                <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                                  <Globe className="h-3 w-3 shrink-0" />
                                  <span className="truncate font-mono">{finding.endpoint}</span>
                                  {finding.cwe && <Badge variant="outline" className="text-[10px] shrink-0">{finding.cwe}</Badge>}
                                  {finding.owasp && <Badge variant="outline" className="text-[10px] shrink-0">{finding.owasp}</Badge>}
                                </div>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <Badge variant="outline" className="text-[10px]">{finding.confidence}%</Badge>
                                <Button
                                  size="sm" variant="outline"
                                  className="h-6 text-[10px] gap-1 px-2"
                                  onClick={(e) => { e.stopPropagation(); setVerifyFinding(finding); }}
                                >
                                  <Shield className="h-3 w-3" /> Verify
                                </Button>
                                <Eye className="h-3 w-3 text-muted-foreground" />
                              </div>
                            </div>
                          </Card>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
};
