/**
 * OmniSec™ © HARSH MALIK
 * LiveFindingsStream — streams every finding as it's discovered (Supabase Realtime
 * on recon_findings + scanResult.findings merge) with full details + Retest button.
 */
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { supabase } from "@/integrations/supabase/client";
import { FindingVerificationPanel } from "@/components/FindingVerificationPanel";
import {
  Activity, ChevronDown, ChevronRight, Bug, Shield, Code, Play,
  AlertTriangle, CheckCircle, Radio,
} from "lucide-react";

interface LiveFinding {
  id: string;
  severity: string;
  title: string;
  description?: string;
  endpoint?: string;
  url_path?: string;
  target_host?: string;
  subdomain?: string;
  method?: string;
  payload?: string;
  vulnerable_parameter?: string;
  evidence?: any;
  raw_data?: any;
  source_module?: string;
  finding_type?: string;
  owasp?: string;
  mitre?: string[];
  cwe?: string;
  cvss?: number;
  confidence?: number;
  verification_status?: string;
  remediation?: string;
  poc?: string;
  exploitCode?: string;
  category?: string;
  first_seen?: string;
  _source: "live" | "scan";
}

interface Props {
  target: string;
  scanId: string | null;
  isScanning: boolean;
  scanFindings: any[];
}

const sevColor = (s: string) => {
  const k = (s || "").toLowerCase();
  if (k === "critical") return "bg-destructive/20 text-destructive border-destructive/40";
  if (k === "high") return "bg-orange-500/20 text-orange-400 border-orange-500/40";
  if (k === "medium") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
  if (k === "low") return "bg-primary/20 text-primary border-primary/40";
  return "bg-muted text-muted-foreground border-border";
};

const normalizeHost = (t: string) =>
  (t || "").replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

export const LiveFindingsStream = ({ target, scanId, isScanning, scanFindings }: Props) => {
  const [liveRows, setLiveRows] = useState<LiveFinding[]>([]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [retestFinding, setRetestFinding] = useState<LiveFinding | null>(null);

  // Subscribe to recon_findings inserts for this target host
  useEffect(() => {
    const host = normalizeHost(target);
    if (!host) return;

    // Initial backfill (last 200 for this host)
    (async () => {
      const { data } = await supabase
        .from("recon_findings")
        .select("*")
        .ilike("target_host", `%${host}%`)
        .order("created_at", { ascending: false })
        .limit(200);
      if (data) {
        setLiveRows(
          data.map((r: any) => ({
            ...r,
            _source: "live" as const,
            endpoint: r.url_path,
          }))
        );
      }
    })();

    const channel = supabase
      .channel(`live-findings-${host}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "recon_findings" },
        (payload) => {
          const row = payload.new as any;
          const rowHost = (row.target_host || "").toLowerCase();
          if (!rowHost.includes(host)) return;
          setLiveRows((prev) => {
            if (prev.some((p) => p.id === row.id)) return prev;
            return [{ ...row, _source: "live", endpoint: row.url_path }, ...prev];
          });
        }
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "recon_findings" },
        (payload) => {
          const row = payload.new as any;
          setLiveRows((prev) => prev.map((p) => (p.id === row.id ? { ...p, ...row } : p)));
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [target]);

  // Merge scanResult.findings with live rows (dedupe by id+title+endpoint)
  const merged = useMemo<LiveFinding[]>(() => {
    const fromScan: LiveFinding[] = (scanFindings || []).map((f: any) => ({
      id: f.id || `scan-${f.title}-${f.endpoint}`,
      severity: f.severity || "info",
      title: f.title || "Finding",
      description: f.description,
      endpoint: f.endpoint,
      method: f.method,
      payload: f.payload,
      evidence: f.evidence,
      vulnerable_parameter: f.vulnerable_parameter,
      owasp: f.owasp,
      mitre: f.mitre,
      cwe: f.cwe,
      cvss: f.cvss,
      confidence: f.confidence,
      remediation: f.remediation,
      poc: f.poc,
      exploitCode: f.exploitCode,
      category: f.category,
      source_module: f.category || "scanner",
      verification_status: f.dualConfirmed ? "confirmed" : "pending",
      _source: "scan" as const,
    }));
    const seen = new Set<string>();
    const all = [...liveRows, ...fromScan];
    return all.filter((f) => {
      const k = `${(f.title || "").toLowerCase()}|${(f.endpoint || f.url_path || "").toLowerCase()}|${(f.vulnerable_parameter || "").toLowerCase()}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }, [liveRows, scanFindings]);

  const handleRetest = (f: LiveFinding) => {
    setRetestFinding(f);
  };

  if (retestFinding) {
    const adapted: any = {
      id: retestFinding.id,
      severity: retestFinding.severity,
      title: retestFinding.title,
      description: retestFinding.description || "",
      endpoint: retestFinding.endpoint || retestFinding.url_path || "",
      method: retestFinding.method || "GET",
      payload: retestFinding.payload,
      evidence:
        typeof retestFinding.evidence === "string"
          ? retestFinding.evidence
          : JSON.stringify(retestFinding.evidence || {}, null, 2),
      remediation: retestFinding.remediation || "Apply standard remediation for this class.",
      cwe: retestFinding.cwe,
      cvss: retestFinding.cvss,
      confidence: retestFinding.confidence || 70,
      poc: retestFinding.poc,
      exploitCode: retestFinding.exploitCode,
      category: retestFinding.category || retestFinding.finding_type,
    };
    return (
      <FindingVerificationPanel
        finding={adapted}
        onClose={() => setRetestFinding(null)}
        onStatusChange={(_id, status) => {
          setLiveRows((prev) =>
            prev.map((p) =>
              p.id === retestFinding.id ? { ...p, verification_status: status } : p
            )
          );
        }}
      />
    );
  }

  return (
    <Card className="p-4 border-primary/30">
      <div className="flex items-center gap-2 mb-3">
        <Radio className={`h-4 w-4 ${isScanning ? "text-green-400 animate-pulse" : "text-muted-foreground"}`} />
        <h3 className="font-semibold text-sm">Live Findings Stream</h3>
        <Badge variant="outline" className="text-xs ml-auto">
          {merged.length} total
        </Badge>
        {isScanning && (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/40 text-xs">
            <Activity className="h-3 w-3 mr-1" />
            streaming
          </Badge>
        )}
      </div>

      <ScrollArea className="h-[560px] pr-2">
        <div className="space-y-2">
          {merged.length === 0 && (
            <div className="text-center py-12 text-muted-foreground text-sm">
              {isScanning ? "Waiting for first finding..." : "No findings yet — start a scan."}
            </div>
          )}
          {merged.map((f) => {
            const isOpen = openId === f.id;
            return (
              <Collapsible
                key={f.id}
                open={isOpen}
                onOpenChange={(v) => setOpenId(v ? f.id : null)}
              >
                <Card className="border-border/40 overflow-hidden">
                  <CollapsibleTrigger asChild>
                    <button className="w-full text-left p-3 hover:bg-muted/30 transition flex items-start gap-2">
                      {isOpen ? (
                        <ChevronDown className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
                      ) : (
                        <ChevronRight className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
                      )}
                      <Badge className={`${sevColor(f.severity)} text-[10px] uppercase font-bold shrink-0`}>
                        {f.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{f.title}</div>
                        <div className="text-xs text-muted-foreground truncate font-mono">
                          {f.method || "GET"} {f.endpoint || f.url_path || f.target_host}
                          {f.vulnerable_parameter && ` · param: ${f.vulnerable_parameter}`}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {f.owasp && (
                          <Badge variant="outline" className="text-[10px] font-mono">
                            {f.owasp}
                          </Badge>
                        )}
                        {f.verification_status === "confirmed" && (
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/40 text-[10px]">
                            <CheckCircle className="h-2.5 w-2.5 mr-0.5" />
                            confirmed
                          </Badge>
                        )}
                        {f.verification_status === "false_positive" && (
                          <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/40 text-[10px]">
                            FP
                          </Badge>
                        )}
                      </div>
                    </button>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="border-t border-border/40 p-3 bg-background/50 space-y-2 text-xs">
                      {f.description && (
                        <div>
                          <div className="text-muted-foreground mb-0.5">Description</div>
                          <div>{f.description}</div>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <div className="text-muted-foreground">Source Module</div>
                          <div className="font-mono">{f.source_module || f.category || "—"}</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Confidence</div>
                          <div>{f.confidence ?? "—"}{typeof f.confidence === "number" ? "%" : ""}</div>
                        </div>
                        {f.cwe && (
                          <div>
                            <div className="text-muted-foreground">CWE</div>
                            <div className="font-mono">{f.cwe}</div>
                          </div>
                        )}
                        {f.cvss && (
                          <div>
                            <div className="text-muted-foreground">CVSS</div>
                            <div className="font-mono">{f.cvss}</div>
                          </div>
                        )}
                        {f.mitre && f.mitre.length > 0 && (
                          <div className="col-span-2">
                            <div className="text-muted-foreground">MITRE ATT&CK</div>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {f.mitre.map((m) => (
                                <Badge key={m} variant="outline" className="text-[10px] font-mono">{m}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {f.payload && (
                        <div>
                          <div className="text-muted-foreground mb-0.5 flex items-center gap-1">
                            <Code className="h-3 w-3" /> Payload Used
                          </div>
                          <pre className="bg-muted/50 p-2 rounded font-mono text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
                            {f.payload}
                          </pre>
                        </div>
                      )}

                      {f.evidence && (
                        <div>
                          <div className="text-muted-foreground mb-0.5 flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" /> Evidence / Action Taken
                          </div>
                          <pre className="bg-muted/50 p-2 rounded font-mono text-[11px] overflow-x-auto max-h-40 whitespace-pre-wrap break-all">
                            {typeof f.evidence === "string"
                              ? f.evidence
                              : JSON.stringify(f.evidence, null, 2)}
                          </pre>
                        </div>
                      )}

                      {f.raw_data && (
                        <div>
                          <div className="text-muted-foreground mb-0.5">Raw Data</div>
                          <pre className="bg-muted/50 p-2 rounded font-mono text-[10px] overflow-x-auto max-h-32 whitespace-pre-wrap break-all">
                            {JSON.stringify(f.raw_data, null, 2)}
                          </pre>
                        </div>
                      )}

                      {f.remediation && (
                        <div>
                          <div className="text-muted-foreground mb-0.5 flex items-center gap-1">
                            <Shield className="h-3 w-3" /> Remediation
                          </div>
                          <div>{f.remediation}</div>
                        </div>
                      )}

                      <div className="flex gap-2 pt-2">
                        <Button
                          size="sm"
                          className="gap-1"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRetest(f);
                          }}
                        >
                          <Play className="h-3 w-3" /> Retest with Exploit Engine
                        </Button>
                        <Badge variant="outline" className="text-[10px] ml-auto">
                          {f._source === "live" ? "live stream" : "scan result"}
                        </Badge>
                      </div>
                    </div>
                  </CollapsibleContent>
                </Card>
              </Collapsible>
            );
          })}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LiveFindingsStream;
