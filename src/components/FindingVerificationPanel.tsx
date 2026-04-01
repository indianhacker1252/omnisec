/**
 * Finding Verification & POC Generator Panel
 * - Verify tab: AI generates editable test script, runs it, shows request/response
 * - POC tab: After confirmation, generates a professional bug bounty report
 */
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import {
  Play, Copy, CheckCircle, XCircle, AlertTriangle, Code, FileText,
  Shield, Terminal, RefreshCw, Wand2, Download, Bug
} from "lucide-react";

interface Finding {
  id: string;
  severity: string;
  title: string;
  description: string;
  endpoint: string;
  method?: string;
  payload?: string;
  evidence?: string;
  evidence2?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  confidence: number;
  poc?: string;
  exploitCode?: string;
  dualConfirmed?: boolean;
  category?: string;
}

interface VerificationResult {
  status: "pending" | "running" | "confirmed" | "not_confirmed" | "error";
  request: string;
  response: string;
  statusCode?: number;
  responseTime?: number;
  analysis: string;
}

interface Props {
  finding: Finding;
  onClose: () => void;
  onStatusChange?: (findingId: string, status: "confirmed" | "false_positive") => void;
}

export const FindingVerificationPanel = ({ finding, onClose, onStatusChange }: Props) => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("verify");
  const [testScript, setTestScript] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [pocReport, setPocReport] = useState("");
  const [isGeneratingPOC, setIsGeneratingPOC] = useState(false);

  const generateTestScript = async () => {
    setIsGenerating(true);
    try {
      const { data, error } = await supabase.functions.invoke("verify-finding", {
        body: {
          action: "generate_script",
          finding: {
            title: finding.title,
            endpoint: finding.endpoint,
            method: finding.method || "GET",
            payload: finding.payload,
            evidence: finding.evidence,
            cwe: finding.cwe,
            category: finding.category,
            severity: finding.severity,
          },
        },
      });
      if (error) throw error;
      setTestScript(data.script || "# Failed to generate script");
      toast({ title: "Test Script Generated", description: "Review and edit, then click Run to verify" });
    } catch (e: any) {
      console.error("Script gen error:", e);
      // Fallback: generate a basic script locally
      setTestScript(generateFallbackScript(finding));
      toast({ title: "Generated Fallback Script", description: "AI unavailable, using template script", variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  };

  const runVerification = async () => {
    if (!testScript.trim()) {
      toast({ title: "No Script", description: "Generate or write a test script first", variant: "destructive" });
      return;
    }
    setIsRunning(true);
    setVerificationResult({ status: "running", request: "", response: "", analysis: "" });

    try {
      const { data, error } = await supabase.functions.invoke("verify-finding", {
        body: {
          action: "run_verification",
          script: testScript,
          finding: {
            title: finding.title,
            endpoint: finding.endpoint,
            method: finding.method || "GET",
            payload: finding.payload,
            evidence: finding.evidence,
            cwe: finding.cwe,
            severity: finding.severity,
          },
        },
      });
      if (error) throw error;
      setVerificationResult({
        status: data.confirmed ? "confirmed" : "not_confirmed",
        request: data.request || "",
        response: data.response || "",
        statusCode: data.statusCode,
        responseTime: data.responseTime,
        analysis: data.analysis || "",
      });

      if (data.confirmed) {
        toast({ title: "✅ Vulnerability Confirmed!", description: "The finding has been verified. Generate a POC report." });
      } else {
        toast({ title: "⚠️ Not Confirmed", description: "The test didn't reproduce the vulnerability", variant: "destructive" });
      }
    } catch (e: any) {
      console.error("Verification error:", e);
      setVerificationResult({
        status: "error",
        request: testScript,
        response: e.message || "Verification failed",
        analysis: "Error during verification. Check the script and try again.",
      });
      toast({ title: "Verification Error", description: e.message, variant: "destructive" });
    } finally {
      setIsRunning(false);
    }
  };

  const generatePOCReport = async () => {
    setIsGeneratingPOC(true);
    try {
      const { data, error } = await supabase.functions.invoke("verify-finding", {
        body: {
          action: "generate_poc",
          finding: {
            title: finding.title,
            endpoint: finding.endpoint,
            method: finding.method || "GET",
            payload: finding.payload,
            evidence: finding.evidence,
            evidence2: finding.evidence2,
            cwe: finding.cwe,
            cvss: finding.cvss,
            severity: finding.severity,
            description: finding.description,
            remediation: finding.remediation,
            category: finding.category,
          },
          verificationResult: verificationResult ? {
            request: verificationResult.request,
            response: verificationResult.response,
            statusCode: verificationResult.statusCode,
            analysis: verificationResult.analysis,
          } : null,
        },
      });
      if (error) throw error;
      setPocReport(data.report || "Failed to generate POC report");
      setActiveTab("poc");
      toast({ title: "POC Report Generated", description: "Ready for bug bounty submission" });
    } catch (e: any) {
      console.error("POC gen error:", e);
      setPocReport(generateFallbackPOC(finding, verificationResult));
      setActiveTab("poc");
      toast({ title: "Generated Fallback POC", variant: "destructive" });
    } finally {
      setIsGeneratingPOC(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: `${label} Copied!` });
  };

  const downloadPOC = () => {
    const blob = new Blob([pocReport], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `POC_${finding.title.replace(/[^a-zA-Z0-9]/g, "_")}.md`;
    a.click();
    URL.revokeObjectURL(url);
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

  const getStatusIcon = () => {
    if (!verificationResult) return null;
    switch (verificationResult.status) {
      case "confirmed": return <CheckCircle className="h-5 w-5 text-green-400" />;
      case "not_confirmed": return <XCircle className="h-5 w-5 text-yellow-400" />;
      case "error": return <AlertTriangle className="h-5 w-5 text-destructive" />;
      case "running": return <RefreshCw className="h-5 w-5 text-primary animate-spin" />;
      default: return null;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" />
      <Card className="relative z-10 w-full max-w-4xl max-h-[92vh] flex flex-col border-primary/30 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>

        {/* Header */}
        <div className="p-4 border-b border-border flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <Badge className={`border text-xs ${getSeverityStyle(finding.severity)}`}>{finding.severity.toUpperCase()}</Badge>
              {finding.cwe && <Badge variant="outline" className="text-xs font-mono">{finding.cwe}</Badge>}
              {verificationResult?.status === "confirmed" && (
                <Badge className="bg-green-500/20 text-green-400 border-green-500/50 text-xs gap-1">
                  <CheckCircle className="h-3 w-3" /> VERIFIED
                </Badge>
              )}
            </div>
            <h2 className="text-base font-bold truncate">{finding.title}</h2>
            <p className="text-xs text-muted-foreground font-mono truncate">{finding.endpoint}</p>
          </div>
          <Button size="sm" variant="ghost" onClick={onClose} className="shrink-0">✕</Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
          <TabsList className="grid grid-cols-2 mx-4 mt-3">
            <TabsTrigger value="verify" className="gap-1 text-xs">
              <Bug className="h-3 w-3" /> Verify Finding
            </TabsTrigger>
            <TabsTrigger value="poc" className="gap-1 text-xs" disabled={verificationResult?.status !== "confirmed" && !pocReport}>
              <FileText className="h-3 w-3" /> POC Report
            </TabsTrigger>
          </TabsList>

          {/* VERIFY TAB */}
          <TabsContent value="verify" className="flex-1 px-4 pb-4 overflow-hidden flex flex-col">
            <div className="flex items-center justify-between mb-3 mt-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">Verification Test Script</span>
                {getStatusIcon()}
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" onClick={generateTestScript} disabled={isGenerating || isRunning} className="text-xs gap-1">
                  {isGenerating ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {testScript ? "Regenerate" : "Generate Script"}
                </Button>
                <Button size="sm" onClick={runVerification} disabled={isRunning || !testScript.trim()} className="text-xs gap-1">
                  {isRunning ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                  Run Verification
                </Button>
              </div>
            </div>

            {/* Editable Script */}
            <Textarea
              value={testScript}
              onChange={(e) => setTestScript(e.target.value)}
              placeholder="Click 'Generate Script' to create a verification test, or write your own..."
              className="flex-1 min-h-[160px] font-mono text-xs bg-background border-border/50 resize-none"
              spellCheck={false}
            />

            {/* Verification Result */}
            {verificationResult && verificationResult.status !== "pending" && (
              <div className="mt-3 space-y-3 flex-shrink-0">
                {/* Status Banner */}
                <div className={`p-3 rounded-lg border flex items-center gap-3 ${
                  verificationResult.status === "confirmed" ? "bg-green-500/10 border-green-500/30" :
                  verificationResult.status === "not_confirmed" ? "bg-yellow-500/10 border-yellow-500/30" :
                  verificationResult.status === "error" ? "bg-destructive/10 border-destructive/30" :
                  "bg-primary/10 border-primary/30"
                }`}>
                  {getStatusIcon()}
                  <div className="flex-1">
                    <p className="text-sm font-medium">
                      {verificationResult.status === "confirmed" ? "Vulnerability Confirmed ✅" :
                       verificationResult.status === "not_confirmed" ? "Not Reproduced ⚠️" :
                       verificationResult.status === "error" ? "Verification Error" :
                       "Running..."}
                    </p>
                    {verificationResult.statusCode && (
                      <p className="text-xs text-muted-foreground">
                        Status: {verificationResult.statusCode} | Response Time: {verificationResult.responseTime}ms
                      </p>
                    )}
                  </div>
                  {verificationResult.status === "confirmed" && (
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" className="text-xs gap-1" onClick={generatePOCReport} disabled={isGeneratingPOC}>
                        {isGeneratingPOC ? <RefreshCw className="h-3 w-3 animate-spin" /> : <FileText className="h-3 w-3" />}
                        Generate POC
                      </Button>
                      {onStatusChange && (
                        <Button size="sm" className="text-xs gap-1 bg-green-600 hover:bg-green-700" onClick={() => onStatusChange(finding.id, "confirmed")}>
                          <CheckCircle className="h-3 w-3" /> Confirm
                        </Button>
                      )}
                    </div>
                  )}
                  {verificationResult.status === "not_confirmed" && onStatusChange && (
                    <Button size="sm" variant="outline" className="text-xs gap-1" onClick={() => onStatusChange(finding.id, "false_positive")}>
                      <XCircle className="h-3 w-3" /> Mark False Positive
                    </Button>
                  )}
                </div>

                {/* Request/Response */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-muted-foreground">REQUEST</span>
                      <Button size="sm" variant="ghost" className="h-6 text-[10px]" onClick={() => copyToClipboard(verificationResult.request, "Request")}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <ScrollArea className="h-32 bg-background rounded border border-border/50 p-2">
                      <pre className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap">{verificationResult.request || "N/A"}</pre>
                    </ScrollArea>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-muted-foreground">RESPONSE</span>
                      <Button size="sm" variant="ghost" className="h-6 text-[10px]" onClick={() => copyToClipboard(verificationResult.response, "Response")}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <ScrollArea className="h-32 bg-background rounded border border-border/50 p-2">
                      <pre className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap">{verificationResult.response || "N/A"}</pre>
                    </ScrollArea>
                  </div>
                </div>

                {/* AI Analysis */}
                {verificationResult.analysis && (
                  <div className="p-3 bg-primary/5 rounded border border-primary/20">
                    <div className="flex items-center gap-1 mb-1">
                      <Shield className="h-3 w-3 text-primary" />
                      <span className="text-xs font-medium">AI Analysis</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{verificationResult.analysis}</p>
                  </div>
                )}
              </div>
            )}
          </TabsContent>

          {/* POC TAB */}
          <TabsContent value="poc" className="flex-1 px-4 pb-4 overflow-hidden flex flex-col">
            <div className="flex items-center justify-between mb-3 mt-2">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">Bug Bounty POC Report</span>
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => copyToClipboard(pocReport, "POC Report")} disabled={!pocReport} className="text-xs gap-1">
                  <Copy className="h-3 w-3" /> Copy
                </Button>
                <Button size="sm" variant="outline" onClick={downloadPOC} disabled={!pocReport} className="text-xs gap-1">
                  <Download className="h-3 w-3" /> Download .md
                </Button>
                <Button size="sm" onClick={generatePOCReport} disabled={isGeneratingPOC} className="text-xs gap-1">
                  {isGeneratingPOC ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  Regenerate
                </Button>
              </div>
            </div>

            {/* Editable POC */}
            <Textarea
              value={pocReport}
              onChange={(e) => setPocReport(e.target.value)}
              placeholder="POC report will appear here after verification..."
              className="flex-1 min-h-[400px] font-mono text-xs bg-background border-border/50 resize-none"
              spellCheck={false}
            />
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
};

// ── Fallback generators when AI is unavailable ──

function generateFallbackScript(finding: Finding): string {
  const url = finding.endpoint;
  const method = finding.method || "GET";
  const payload = finding.payload || "";

  if (finding.cwe === "CWE-89" || finding.category === "sqli" || finding.title?.toLowerCase().includes("sql")) {
    return `# SQL Injection Verification Script
# Finding: ${finding.title}
# Endpoint: ${url}
# Method: ${method}

# Test 1: Error-based SQLi
curl -v "${url}${url.includes("?") ? "&" : "?"}id=${encodeURIComponent(payload || "1' OR '1'='1")}"

# Test 2: Boolean-based blind
curl -s -o /dev/null -w "%{http_code}" "${url}${url.includes("?") ? "&" : "?"}id=1 AND 1=1"
curl -s -o /dev/null -w "%{http_code}" "${url}${url.includes("?") ? "&" : "?"}id=1 AND 1=2"

# Test 3: Time-based blind
curl -s -o /dev/null -w "%{time_total}" "${url}${url.includes("?") ? "&" : "?"}id=1; WAITFOR DELAY '0:0:3'--"

# Expected: Different responses between Test 2 commands = SQLi confirmed
# Expected: ~3s delay in Test 3 = Blind SQLi confirmed`;
  }

  if (finding.cwe === "CWE-79" || finding.category === "xss" || finding.title?.toLowerCase().includes("xss")) {
    return `# XSS Verification Script
# Finding: ${finding.title}
# Endpoint: ${url}

# Test 1: Basic reflected XSS
curl -v "${url}${url.includes("?") ? "&" : "?"}q=${encodeURIComponent(payload || '<script>alert(1)</script>')}"

# Test 2: Event handler XSS
curl -v "${url}${url.includes("?") ? "&" : "?"}q=${encodeURIComponent('<img src=x onerror=alert(1)>')}"

# Test 3: SVG XSS
curl -v "${url}${url.includes("?") ? "&" : "?"}q=${encodeURIComponent('<svg onload=alert(1)>')}"

# Look for: unescaped payload reflected in response body = XSS confirmed`;
  }

  return `# Vulnerability Verification Script
# Finding: ${finding.title}
# Endpoint: ${url}
# Method: ${method}
# CWE: ${finding.cwe || "N/A"}

# Test the endpoint with the original payload
curl -v -X ${method} "${url}" ${payload ? `-d "${payload}"` : ""}

# Check response for vulnerability indicators
# Expected evidence: ${finding.evidence || "Review response manually"}`;
}

function generateFallbackPOC(finding: Finding, result: VerificationResult | null): string {
  return `# Bug Bounty Report — ${finding.title}

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability** | ${finding.title} |
| **Severity** | ${finding.severity.toUpperCase()} |
| **CWE** | ${finding.cwe || "N/A"} |
| **CVSS** | ${finding.cvss || "N/A"} |
| **Endpoint** | \`${finding.endpoint}\` |
| **Method** | ${finding.method || "GET"} |

## Description
${finding.description}

## Steps to Reproduce
1. Navigate to \`${finding.endpoint}\`
2. Inject the following payload: \`${finding.payload || "N/A"}\`
3. Observe the response for vulnerability indicators

## Proof of Concept

### Request
\`\`\`
${result?.request || `curl -v -X ${finding.method || "GET"} "${finding.endpoint}" ${finding.payload ? `-d "${finding.payload}"` : ""}`}
\`\`\`

### Response
\`\`\`
${result?.response || finding.evidence || "See evidence below"}
\`\`\`

## Evidence
${finding.evidence || "N/A"}
${finding.evidence2 ? `\n### Secondary Verification\n${finding.evidence2}` : ""}

## Impact
This vulnerability allows an attacker to potentially compromise the application's ${finding.cwe === "CWE-89" ? "database integrity and confidentiality" : finding.cwe === "CWE-79" ? "user sessions and perform actions on behalf of victims" : "security posture"}.

## Remediation
${finding.remediation}
`;
}
