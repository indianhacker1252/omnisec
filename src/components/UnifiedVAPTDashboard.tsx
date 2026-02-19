/**
 * OmniSec™ Unified VAPT Dashboard v5.0
 * - Real-time live scan output via Supabase Realtime
 * - Subdomain Attack Surface Map
 * - Dedicated CORS/Traversal/Cookie findings tab
 * - Clickable finding detail modal with full POC
 * - AI learning with false positive feedback loop
 */

import { useState, useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { SubdomainAttackMap } from "@/components/SubdomainAttackMap";
import { FindingDetailModal } from "@/components/FindingDetailModal";
import {
  Brain,
  Zap,
  Target,
  Shield,
  Globe,
  Play,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Activity,
  Eye,
  ThumbsUp,
  ThumbsDown,
  Crosshair,
  Radar,
  Bug,
  Code,
  Network,
  Lock,
  Terminal,
  Layers,
  GitBranch,
  Wifi,
  Cookie,
  FolderOpen,
  Filter,
  ChevronRight
} from "lucide-react";

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
  mitre?: string[];
  confidence: number;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
  dualConfirmed?: boolean;
  retryCount?: number;
}

interface LiveLogEntry {
  timestamp: string;
  phase: string;
  message: string;
  progress: number;
  findings: number;
  endpoints: number;
  currentEndpoint?: string;
}

interface ScanResult {
  success: boolean;
  target: string;
  scanTime: number;
  discovery: {
    endpoints: number;
    subdomains: number;
    forms: number;
    apis: number;
  };
  fingerprint: any;
  findings: Finding[];
  attackPaths: any[];
  chainedExploits: any[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recommendations: string[];
  subdomains?: string[];
}

const PHASE_LABELS: Record<string, string> = {
  discovery: "🔍 Endpoint Discovery",
  subdomain_enum: "🌐 Subdomain Enumeration",
  fingerprint: "🖐 Fingerprinting",
  vuln_assessment: "⚡ Vulnerability Assessment",
  cors_scan: "🔀 CORS Misconfiguration",
  traversal_scan: "📂 Directory Traversal",
  cookie_scan: "🍪 Cookie/Session Audit",
  injection: "💉 Deep Injection Testing",
  auth: "🔑 Auth & Authorization",
  business_logic: "🧠 Business Logic / IDOR",
  correlation: "🤖 AI Correlation & Attack Paths",
  poc: "📋 POC Generation",
  learning: "📚 AI Learning Update",
  complete: "✅ Scan Complete",
};

export const UnifiedVAPTDashboard = () => {
  const { toast } = useToast();

  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [liveFindings, setLiveFindings] = useState(0);
  const [liveEndpoints, setLiveEndpoints] = useState(0);
  const [currentEndpoint, setCurrentEndpoint] = useState("");
  const [liveLogs, setLiveLogs] = useState<LiveLogEntry[]>([]);
  const [subdomainFilter, setSubdomainFilter] = useState<string | null>(null);
  const [activeResultTab, setActiveResultTab] = useState("findings");

  const logsEndRef = useRef<HTMLDivElement>(null);

  // AI Settings
  const [enableLearning, setEnableLearning] = useState(true);
  const [retryWithAI, setRetryWithAI] = useState(true);
  const [generatePOC, setGeneratePOC] = useState(true);
  const [maxDepth, setMaxDepth] = useState(3);

  // Learning stats
  const [learningStats, setLearningStats] = useState({
    totalScans: 0,
    totalFindings: 0,
    learningPoints: 0,
    confirmedVulns: 0,
    falsePositives: 0,
    accuracy: 0,
  });

  useEffect(() => {
    loadLearningStats();
  }, []);

  // Auto-scroll live log
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [liveLogs]);

  // Realtime subscription
  useEffect(() => {
    if (!isScanning) return;

    const channel = supabase
      .channel(`scan-progress-live-${Date.now()}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "scan_progress" },
        (payload: any) => {
          const data = payload.new;
          setProgress(data.progress || 0);
          const phaseLabel = PHASE_LABELS[data.phase] || data.phase;
          setCurrentPhase(phaseLabel);
          setLiveFindings(data.findings_so_far || 0);
          setLiveEndpoints(data.endpoints_discovered || 0);
          if (data.current_endpoint) setCurrentEndpoint(data.current_endpoint);

          setLiveLogs((prev) => [
            ...prev,
            {
              timestamp: new Date().toLocaleTimeString(),
              phase: data.phase,
              message: data.message || phaseLabel,
              progress: data.progress || 0,
              findings: data.findings_so_far || 0,
              endpoints: data.endpoints_discovered || 0,
              currentEndpoint: data.current_endpoint || undefined,
            },
          ]);
        }
      )
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [isScanning]);

  const loadLearningStats = async () => {
    try {
      const [{ data: scans }, { data: actions }, { data: feedback }] = await Promise.all([
        supabase.from("scan_history").select("id, findings_count").limit(200),
        supabase.from("vapt_test_actions").select("outcome_label").limit(1000),
        supabase.from("vapt_feedback").select("rating").limit(500),
      ]);

      const totalScans = scans?.length || 0;
      const totalFindings = scans?.reduce((s, r) => s + (r.findings_count || 0), 0) || 0;
      const confirmed = feedback?.filter((f) => f.rating === "confirmed").length || 0;
      const fps = feedback?.filter((f) => f.rating === "false_positive").length || 0;
      const successActions = actions?.filter((a) => a.outcome_label === "success").length || 0;
      const totalActions = actions?.length || 1;

      setLearningStats({
        totalScans,
        totalFindings,
        learningPoints: actions?.length || 0,
        confirmedVulns: confirmed,
        falsePositives: fps,
        accuracy: Math.round((successActions / totalActions) * 100),
      });
    } catch (e) {
      console.error("Failed to load stats:", e);
    }
  };

  const runAutonomousVAPT = async () => {
    if (!target.trim()) {
      toast({ title: "Target Required", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setProgress(0);
    setLiveFindings(0);
    setLiveEndpoints(0);
    setCurrentEndpoint("");
    setScanResult(null);
    setSelectedFinding(null);
    setLiveLogs([]);
    setCurrentPhase("Initializing autonomous scanner...");
    setSubdomainFilter(null);

    try {
      const response = await supabase.functions.invoke("autonomous-vapt", {
        body: { target, action: "full_scan", modules: ["all"], maxDepth, enableLearning, retryWithAI, generatePOC },
      });

      if (response.error) {
        await pollForResults(target);
        return;
      }

      const result = response.data as ScanResult;
      setScanResult(result);
      setProgress(100);
      setCurrentPhase("✅ Scan complete!");
      await loadLearningStats();

      toast({
        title: "Autonomous VAPT Complete",
        description: `Found ${result.findings?.length || 0} vulnerabilities | ${result.discovery?.subdomains || 0} subdomains mapped`,
      });
    } catch {
      await pollForResults(target);
    } finally {
      setIsScanning(false);
    }
  };

  const pollForResults = async (scanTarget: string) => {
    setCurrentPhase("Scan running server-side, polling for results...");
    const cleanDomain = scanTarget.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

    for (let attempt = 0; attempt < 20; attempt++) {
      await new Promise((r) => setTimeout(r, 12000));
      try {
        const { data: scans } = await supabase
          .from("scan_history")
          .select("id, target, status, findings_count, report")
          .ilike("target", `%${cleanDomain}%`)
          .eq("status", "completed")
          .order("created_at", { ascending: false })
          .limit(1);

        if (scans && scans.length > 0) {
          const scan = scans[0];
          const report = scan.report as any;
          const findings = report?.findings || [];
          const sevCounts = {
            critical: findings.filter((f: any) => f.severity === "critical").length,
            high: findings.filter((f: any) => f.severity === "high").length,
            medium: findings.filter((f: any) => f.severity === "medium").length,
            low: findings.filter((f: any) => f.severity === "low").length,
            info: findings.filter((f: any) => f.severity === "info").length,
          };

          setScanResult({
            success: true,
            target: scanTarget,
            scanTime: 0,
            discovery: { endpoints: 0, subdomains: 0, forms: 0, apis: 0 },
            fingerprint: {},
            findings,
            attackPaths: [],
            chainedExploits: [],
            summary: sevCounts,
            recommendations: [],
            subdomains: [],
          });
          setProgress(100);
          setCurrentPhase("✅ Results retrieved from server");
          await loadLearningStats();
          toast({ title: "VAPT Complete", description: `${findings.length} findings for ${cleanDomain}` });
          return;
        }
      } catch {}

      setProgress(Math.min(40 + attempt * 3, 95));
      setCurrentPhase(`Polling for results... (${attempt + 1}/20)`);
    }

    toast({ title: "Scan Still Running", description: "Check back in a moment", variant: "destructive" });
  };

  const markFalsePositive = async (finding: Finding) => {
    try {
      await supabase.from("vapt_feedback").insert({
        rating: "false_positive",
        comments: `FP: ${finding.title} at ${finding.endpoint} — confidence was ${finding.confidence}%`,
      });
      if (scanResult) {
        setScanResult({
          ...scanResult,
          findings: scanResult.findings.map((f) => f.id === finding.id ? { ...f, falsePositive: true } : f),
        });
      }
      setSelectedFinding(null);
      toast({ title: "False Positive Recorded", description: "AI will learn to avoid this in future scans" });
    } catch {
      toast({ title: "Error", variant: "destructive" });
    }
  };

  const confirmVulnerability = async (finding: Finding) => {
    try {
      await supabase.from("vapt_feedback").insert({
        rating: "confirmed",
        comments: `Confirmed: ${finding.title} — ${finding.dualConfirmed ? "dual-confirmed" : "single"} | ${finding.confidence}% confidence`,
      });
      toast({ title: "Confirmed ✓", description: "Added to AI training dataset" });
    } catch {
      toast({ title: "Error", variant: "destructive" });
    }
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

  // Filter helpers
  const allFindings = (scanResult?.findings || []).filter((f) => !f.falsePositive);

  const filteredFindings = subdomainFilter
    ? allFindings.filter((f) => f.endpoint?.includes(subdomainFilter) || f.subdomain === subdomainFilter)
    : allFindings;

  const corsFindings = filteredFindings.filter((f) =>
    f.id?.startsWith("CORS") || f.cwe === "CWE-346" || f.title?.toLowerCase().includes("cors")
  );
  const traversalFindings = filteredFindings.filter((f) =>
    f.id?.startsWith("TRAVERSAL") || f.cwe === "CWE-22" || f.title?.toLowerCase().includes("traversal") || f.title?.toLowerCase().includes("path")
  );
  const cookieFindings = filteredFindings.filter((f) =>
    f.id?.startsWith("COOKIE") || ["CWE-1004", "CWE-614", "CWE-352"].includes(f.cwe || "") || f.title?.toLowerCase().includes("cookie") || f.title?.toLowerCase().includes("session")
  );
  const otherFindings = filteredFindings.filter(
    (f) => !corsFindings.includes(f) && !traversalFindings.includes(f) && !cookieFindings.includes(f)
  );

  const FindingCard = ({ finding }: { finding: Finding }) => (
    <Card
      className={`p-4 cursor-pointer transition-all hover:border-primary/40 hover:bg-primary/5 ${
        selectedFinding?.id === finding.id ? "border-primary bg-primary/10" : "border-border/50"
      }`}
      onClick={() => setSelectedFinding(finding)}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <Badge className={`text-xs border shrink-0 ${getSeverityStyle(finding.severity)}`}>
            {finding.severity.toUpperCase()}
          </Badge>
          {finding.dualConfirmed && (
            <Badge variant="outline" className="text-[10px] border-green-500/50 text-green-400 shrink-0">
              ✓ Confirmed
            </Badge>
          )}
          <span className="font-medium text-sm leading-tight">{finding.title}</span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <Badge variant="outline" className="text-[10px]">{finding.confidence}%</Badge>
          <ChevronRight className="h-3 w-3 text-muted-foreground" />
        </div>
      </div>
      <p className="text-xs text-muted-foreground line-clamp-2 mb-2">{finding.description}</p>
      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
        <Globe className="h-3 w-3 shrink-0" />
        <span className="truncate font-mono">{finding.endpoint}</span>
        {finding.cwe && <Badge variant="outline" className="ml-auto shrink-0 text-[10px]">{finding.cwe}</Badge>}
      </div>
    </Card>
  );

  const EmptyState = ({ label }: { label: string }) => (
    <div className="text-center text-muted-foreground py-12">
      <CheckCircle className="h-10 w-10 mx-auto mb-3 opacity-30" />
      <p className="text-sm">{label}</p>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Finding detail modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onConfirm={confirmVulnerability}
          onFalsePositive={markFalsePositive}
        />
      )}

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <Card className="p-6 border-primary/20 bg-gradient-to-br from-card to-card/80">
        <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary/10 rounded-xl">
              <Crosshair className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Autonomous VAPT Engine</h1>
              <p className="text-muted-foreground text-sm">XBOW-like AI-powered penetration testing v5.0</p>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <Badge variant="outline" className="gap-1 px-3 py-1">
              <Brain className="h-4 w-4" />
              {learningStats.learningPoints} Learning Points
            </Badge>
            <Badge variant="outline" className="gap-1 px-3 py-1">
              <TrendingUp className="h-4 w-4" />
              {learningStats.accuracy}% Accuracy
            </Badge>
            {learningStats.falsePositives > 0 && (
              <Badge variant="outline" className="gap-1 px-3 py-1 border-yellow-500/50 text-yellow-400">
                <ThumbsDown className="h-3 w-3" />
                {learningStats.falsePositives} FPs filtered
              </Badge>
            )}
          </div>
        </div>

        {/* Target Input */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="md:col-span-3">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !isScanning && runAutonomousVAPT()}
              placeholder="Enter target: testphp.vulnweb.com, example.com, https://target.com"
              className="h-14 text-base"
              disabled={isScanning}
            />
          </div>
          <Button onClick={runAutonomousVAPT} disabled={isScanning} className="h-14 text-base gap-2" size="lg">
            {isScanning ? (
              <><RefreshCw className="h-5 w-5 animate-spin" /> Scanning...</>
            ) : (
              <><Radar className="h-5 w-5" /> Start VAPT</>
            )}
          </Button>
        </div>

        {/* Settings */}
        <div className="flex flex-wrap items-center gap-6 p-4 bg-background/50 rounded-lg">
          <div className="flex items-center gap-2">
            <Switch checked={enableLearning} onCheckedChange={setEnableLearning} />
            <span className="text-sm font-medium">AI Learning</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={retryWithAI} onCheckedChange={setRetryWithAI} />
            <span className="text-sm font-medium">Adaptive Payloads</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={generatePOC} onCheckedChange={setGeneratePOC} />
            <span className="text-sm font-medium">Generate POC</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Depth:</span>
            <select
              value={maxDepth}
              onChange={(e) => setMaxDepth(parseInt(e.target.value))}
              className="bg-background border border-border rounded px-2 py-1 text-sm"
              disabled={isScanning}
            >
              <option value="1">Shallow</option>
              <option value="3">Normal</option>
              <option value="5">Deep</option>
            </select>
          </div>
        </div>

        {/* Progress */}
        {isScanning && (
          <div className="mt-6 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4 animate-pulse text-primary" />
                {currentPhase}
              </span>
              <span className="text-sm text-muted-foreground">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
            <div className="grid grid-cols-7 gap-1 text-xs">
              {[
                { label: "Recon", pct: 8 },
                { label: "Subdomains", pct: 18 },
                { label: "Fingerprint", pct: 24 },
                { label: "Vuln Scan", pct: 38 },
                { label: "CORS/Trav/Cookie", pct: 58 },
                { label: "Injection/Auth", pct: 80 },
                { label: "AI/POC", pct: 100 },
              ].map((p) => (
                <div
                  key={p.label}
                  className={`text-center p-1 rounded transition-colors ${
                    progress >= p.pct ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                  }`}
                >
                  {p.label}
                </div>
              ))}
            </div>
            <div className="flex items-center gap-6 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Globe className="h-3 w-3" /> {liveEndpoints} endpoints
              </span>
              <span className="flex items-center gap-1">
                <Bug className="h-3 w-3" /> {liveFindings} findings
              </span>
              {currentEndpoint && (
                <span className="flex items-center gap-1 truncate max-w-xs font-mono text-[10px]">
                  <Target className="h-3 w-3 shrink-0" /> {currentEndpoint}
                </span>
              )}
            </div>
          </div>
        )}
      </Card>

      {/* ── Live Scan Output ──────────────────────────────────────────────────── */}
      {(isScanning || liveLogs.length > 0) && (
        <Card className="p-4 border-primary/20">
          <div className="flex items-center gap-2 mb-3">
            <Terminal className="h-4 w-4 text-primary" />
            <h3 className="font-semibold">Live Scan Output</h3>
            {isScanning && <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse ml-auto" />}
          </div>
          <ScrollArea className="h-48 bg-background rounded border border-border/40 p-3 font-mono text-xs">
            {liveLogs.map((log, i) => (
              <div key={i} className="flex gap-3 py-0.5 hover:bg-primary/5 rounded px-1">
                <span className="text-muted-foreground shrink-0">{log.timestamp}</span>
                <span className="text-primary shrink-0">[{log.progress}%]</span>
                <span className="flex-1">{log.message}</span>
                {log.findings > 0 && (
                  <span className="text-yellow-400 shrink-0">{log.findings}🐛</span>
                )}
                {log.endpoints > 0 && (
                  <span className="text-primary/70 shrink-0">{log.endpoints}🌐</span>
                )}
              </div>
            ))}
            {liveLogs.length === 0 && isScanning && (
              <div className="text-muted-foreground animate-pulse">Waiting for scan events...</div>
            )}
            <div ref={logsEndRef} />
          </ScrollArea>
        </Card>
      )}

      {/* ── Results ──────────────────────────────────────────────────────────── */}
      {scanResult && (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-7 gap-3">
            {[
              { label: "Critical", value: scanResult.summary?.critical || 0, cls: "text-destructive border-destructive/30 bg-destructive/10" },
              { label: "High", value: scanResult.summary?.high || 0, cls: "text-orange-400 border-orange-500/30 bg-orange-500/10" },
              { label: "Medium", value: scanResult.summary?.medium || 0, cls: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" },
              { label: "Low", value: scanResult.summary?.low || 0, cls: "text-primary border-primary/30 bg-primary/10" },
              { label: "Subdomains", value: scanResult.discovery?.subdomains || scanResult.subdomains?.length || 0, cls: "text-primary border-primary/20 bg-primary/5" },
              { label: "Endpoints", value: scanResult.discovery?.endpoints || 0, cls: "text-primary border-primary/20 bg-primary/5" },
              { label: "Scan Time", value: `${Math.round((scanResult.scanTime || 0) / 1000)}s`, cls: "text-muted-foreground border-border bg-muted/30" },
            ].map((s) => (
              <Card key={s.label} className={`p-4 text-center border ${s.cls}`}>
                <div className="text-2xl font-bold">{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </Card>
            ))}
          </div>

          {/* Subdomain filter chip */}
          {subdomainFilter && (
            <div className="flex items-center gap-2 text-sm">
              <Filter className="h-4 w-4 text-primary" />
              <span>Filtered to:</span>
              <Badge variant="outline" className="font-mono gap-1">
                {subdomainFilter}
                <button onClick={() => setSubdomainFilter(null)} className="ml-1 text-muted-foreground hover:text-foreground">×</button>
              </Badge>
            </div>
          )}

          {/* Attack Surface Map */}
          {(scanResult.subdomains?.length || 0) > 0 && (
            <SubdomainAttackMap
              subdomains={scanResult.subdomains || []}
              findings={allFindings}
              onSelectSubdomain={(sub) => {
                setSubdomainFilter(sub);
                setActiveResultTab("findings");
              }}
            />
          )}

          {/* Findings Tabs */}
          <Card className="p-4 border-primary/20">
            <Tabs value={activeResultTab} onValueChange={setActiveResultTab}>
              <TabsList className="grid w-full grid-cols-2 md:grid-cols-5 mb-4">
                <TabsTrigger value="findings" className="gap-1 text-xs">
                  <Bug className="h-3 w-3" />
                  All ({otherFindings.length})
                </TabsTrigger>
                <TabsTrigger value="cors" className="gap-1 text-xs">
                  <Wifi className="h-3 w-3" />
                  CORS ({corsFindings.length})
                </TabsTrigger>
                <TabsTrigger value="traversal" className="gap-1 text-xs">
                  <FolderOpen className="h-3 w-3" />
                  Traversal ({traversalFindings.length})
                </TabsTrigger>
                <TabsTrigger value="cookies" className="gap-1 text-xs">
                  <Cookie className="h-3 w-3" />
                  Cookies ({cookieFindings.length})
                </TabsTrigger>
                <TabsTrigger value="attacks" className="gap-1 text-xs">
                  <Layers className="h-3 w-3" />
                  Attack Paths
                </TabsTrigger>
              </TabsList>

              {/* All Findings */}
              <TabsContent value="findings">
                <ScrollArea className="h-[520px]">
                  <div className="space-y-3 pr-2">
                    {otherFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
                    {otherFindings.length === 0 && <EmptyState label="No general findings" />}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* CORS Findings */}
              <TabsContent value="cors">
                <div className="mb-3 p-3 bg-primary/5 rounded border border-primary/20 text-xs text-muted-foreground">
                  <div className="font-medium text-foreground mb-1 flex items-center gap-1">
                    <Wifi className="h-3 w-3 text-primary" /> CORS Misconfiguration Scanner
                  </div>
                  Tests arbitrary origin reflection via OPTIONS + GET dual-confirmation. Only flags when both methods agree.
                </div>
                <ScrollArea className="h-[460px]">
                  <div className="space-y-3 pr-2">
                    {corsFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
                    {corsFindings.length === 0 && <EmptyState label="No CORS misconfigurations detected — target properly restricts cross-origin requests" />}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Directory Traversal Findings */}
              <TabsContent value="traversal">
                <div className="mb-3 p-3 bg-primary/5 rounded border border-primary/20 text-xs text-muted-foreground">
                  <div className="font-medium text-foreground mb-1 flex items-center gap-1">
                    <FolderOpen className="h-3 w-3 text-primary" /> Directory/Path Traversal Scanner
                  </div>
                  Tests file parameters with multiple encodings (../../../etc/passwd, %2e%2e, etc.). Only flags when file content is actually returned.
                </div>
                <ScrollArea className="h-[460px]">
                  <div className="space-y-3 pr-2">
                    {traversalFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
                    {traversalFindings.length === 0 && <EmptyState label="No path traversal vulnerabilities detected" />}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Cookie / Session Findings */}
              <TabsContent value="cookies">
                <div className="mb-3 p-3 bg-primary/5 rounded border border-primary/20 text-xs text-muted-foreground">
                  <div className="font-medium text-foreground mb-1 flex items-center gap-1">
                    <Cookie className="h-3 w-3 text-primary" /> Cookie & Session Security Auditor
                  </div>
                  Checks HttpOnly, Secure, SameSite flags. HttpOnly issues dual-confirmed by inline script presence (XSS → cookie theft vector).
                </div>
                <ScrollArea className="h-[460px]">
                  <div className="space-y-3 pr-2">
                    {cookieFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
                    {cookieFindings.length === 0 && <EmptyState label="No cookie security issues found — cookies are properly hardened" />}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Attack Paths */}
              <TabsContent value="attacks">
                <ScrollArea className="h-[520px]">
                  <div className="space-y-3 pr-2">
                    {(scanResult.attackPaths || []).map((path, i) => (
                      <Card key={i} className="p-4 border-border/50">
                        <div className="flex items-center gap-2 mb-2">
                          <Layers className="h-4 w-4 text-primary" />
                          <span className="font-semibold">{path.name}</span>
                          {path.mitre && <Badge variant="outline" className="text-xs font-mono ml-auto">{path.mitre}</Badge>}
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">{path.impact}</p>
                        <div className="space-y-1">
                          {(path.steps || []).map((step: string, j: number) => (
                            <div key={j} className="flex items-start gap-2 text-sm">
                              <span className="text-primary font-bold shrink-0">{j + 1}.</span>
                              <span className="text-muted-foreground">{step}</span>
                            </div>
                          ))}
                        </div>
                      </Card>
                    ))}
                    {(!scanResult.attackPaths || scanResult.attackPaths.length === 0) && (
                      <EmptyState label="No multi-step attack paths identified" />
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>
            </Tabs>
          </Card>
        </div>
      )}

      {/* ── AI Learning Stats ─────────────────────────────────────────────────── */}
      <Card className="p-6 border-primary/20">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="h-6 w-6 text-primary" />
          <h3 className="text-lg font-bold">AI Learning Statistics</h3>
          <Badge variant="outline" className="ml-auto text-xs">
            Self-improving with each scan
          </Badge>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          {[
            { label: "Total Scans", value: learningStats.totalScans, icon: <Radar className="h-4 w-4" /> },
            { label: "Findings", value: learningStats.totalFindings, icon: <Bug className="h-4 w-4" /> },
            { label: "Learning Points", value: learningStats.learningPoints, icon: <Brain className="h-4 w-4" /> },
            { label: "Confirmed Vulns", value: learningStats.confirmedVulns, icon: <CheckCircle className="h-4 w-4 text-green-400" /> },
            { label: "FPs Filtered", value: learningStats.falsePositives, icon: <ThumbsDown className="h-4 w-4 text-yellow-400" /> },
            { label: "AI Accuracy", value: `${learningStats.accuracy}%`, icon: <TrendingUp className="h-4 w-4 text-primary" /> },
          ].map((s) => (
            <Card key={s.label} className="p-4 bg-background/50 border-border/30">
              <div className="flex items-center gap-2 mb-1 text-muted-foreground">{s.icon}</div>
              <div className="text-2xl font-bold text-primary">{s.value}</div>
              <div className="text-xs text-muted-foreground">{s.label}</div>
            </Card>
          ))}
        </div>
        <p className="text-xs text-muted-foreground mt-4 leading-relaxed">
          The AI learns from every scan: confirmed vulnerabilities improve payload selection; marked false positives are excluded
          from future reports. Use 👍 / 👎 on findings to train the model. Higher learning points = fewer false positives.
        </p>
      </Card>
    </div>
  );
};

export default UnifiedVAPTDashboard;
