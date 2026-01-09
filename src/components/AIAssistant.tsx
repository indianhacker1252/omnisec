import { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Send, Sparkles } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useScanHistory } from "@/hooks/useScanHistory";

interface Message {
  role: "user" | "assistant";
  content: string;
  metadata?: {
    command?: string;
    target?: string;
    action?: string;
  };
}

const CHAT_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/chat`;

type StreamErrorCode = "rate_limit" | "payment_required" | "http_error";
class StreamError extends Error {
  code: StreamErrorCode;
  status?: number;
  constructor(message: string, code: StreamErrorCode, status?: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function normalizeHost(raw: string) {
  return raw.trim().replace(/^https?:\/\//, "").split("/")[0];
}

function normalizeUrl(raw: string) {
  const t = raw.trim();
  if (t.startsWith("http://") || t.startsWith("https://")) return t;
  return `https://${normalizeHost(t)}`;
}

async function streamChat({
  messages,
  onDelta,
  onDone,
}: {
  messages: Message[];
  onDelta: (deltaText: string) => void;
  onDone: () => void;
}) {
  const resp = await fetch(CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
    },
    body: JSON.stringify({ messages }),
  });

  if (!resp.ok) {
    if (resp.status === 429) throw new StreamError("Rate limited", "rate_limit", resp.status);
    if (resp.status === 402) throw new StreamError("AI credits exhausted", "payment_required", resp.status);
    throw new StreamError(`Chat failed (${resp.status})`, "http_error", resp.status);
  }

  if (!resp.body) {
    throw new StreamError("Chat stream body missing", "http_error", resp.status);
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let textBuffer = "";
  let streamDone = false;

  while (!streamDone) {
    const { done, value } = await reader.read();
    if (done) break;
    textBuffer += decoder.decode(value, { stream: true });

    let newlineIndex: number;
    while ((newlineIndex = textBuffer.indexOf("\n")) !== -1) {
      let line = textBuffer.slice(0, newlineIndex);
      textBuffer = textBuffer.slice(newlineIndex + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (line.startsWith(":") || line.trim() === "") continue;
      if (!line.startsWith("data: ")) continue;
      const jsonStr = line.slice(6).trim();
      if (jsonStr === "[DONE]") {
        streamDone = true;
        break;
      }
      try {
        const parsed = JSON.parse(jsonStr);
        const content = parsed.choices?.[0]?.delta?.content as string | undefined;
        if (content) onDelta(content);
      } catch {
        textBuffer = line + "\n" + textBuffer;
        break;
      }
    }
  }

  if (textBuffer.trim()) {
    for (let raw of textBuffer.split("\n")) {
      if (!raw) continue;
      if (raw.endsWith("\r")) raw = raw.slice(0, -1);
      if (raw.startsWith(":") || raw.trim() === "") continue;
      if (!raw.startsWith("data: ")) continue;
      const jsonStr = raw.slice(6).trim();
      if (jsonStr === "[DONE]") continue;
      try {
        const parsed = JSON.parse(jsonStr);
        const content = parsed.choices?.[0]?.delta?.content as string | undefined;
        if (content) onDelta(content);
      } catch {
        // ignore
      }
    }
  }

  onDone();
}

export const AIAssistant = () => {
  const { toast } = useToast();
  const { logScan, completeScan, saveReport, createAlert } = useScanHistory();

  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: `OmniSec AI Assistant online. Commands:
• "scan example.com" - Quick domain scan
• "full audit example.com" - Complete security audit (Recon + Web + API + Cloud + IAM)
• "red team example.com" - Full VAPT with all modules
• "pentest example.com" - Penetration testing workflow`,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  }, [messages]);

  const appendAssistantMessage = (content: string) => {
    setMessages((prev) => [...prev, { role: "assistant", content }]);
  };

  const updateLastAssistantMessage = (content: string) => {
    setMessages((prev) => {
      const last = prev[prev.length - 1];
      if (last?.role === "assistant") {
        return prev.map((m, i) => (i === prev.length - 1 ? { ...m, content } : m));
      }
      return [...prev, { role: "assistant", content }];
    });
  };

  // Basic domain scan (Recon + Web + VulnIntel)
  const runDomainScanWorkflow = async (rawTarget: string) => {
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    toast({ title: "Domain scan started", description: `Running Recon + WebApp + VulnIntel for ${host}` });

    const [reconScanId, webScanId, vulnScanId] = await Promise.all([
      logScan({ module: 'recon', scanType: 'Auto Reconnaissance', target: host }),
      logScan({ module: 'webapp', scanType: 'Auto Web Security Scan', target: url }),
      logScan({ module: 'vuln', scanType: 'Auto Vulnerability Intel', target: host }),
    ]);

    const [reconResp, webResp, vulnResp] = await Promise.all([
      supabase.functions.invoke('recon', { body: { target: host } }),
      supabase.functions.invoke('webapp-scan', { body: { target: url } }),
      supabase.functions.invoke('vulnintel', { body: { query: host } }),
    ]);

    if (reconResp.error) throw reconResp.error;
    if (webResp.error) throw webResp.error;
    if (vulnResp.error) throw vulnResp.error;

    const reconData: any = reconResp.data;
    const webData: any = webResp.data;
    const vulnData: any = vulnResp.data;

    const reconCount = Array.isArray(reconData?.ports) ? reconData.ports.length : 0;
    const webCount = Array.isArray(webData?.findings) ? webData.findings.length : 0;
    const vulnCount = vulnData?.count ?? (Array.isArray(vulnData?.vulnerabilities) ? vulnData.vulnerabilities.length : 0);

    await Promise.all([
      reconScanId ? completeScan(reconScanId, { status: 'completed', findingsCount: reconCount, report: reconData }) : Promise.resolve(),
      webScanId ? completeScan(webScanId, { status: 'completed', findingsCount: webCount, report: webData }) : Promise.resolve(),
      vulnScanId ? completeScan(vulnScanId, { status: 'completed', findingsCount: vulnCount, report: vulnData }) : Promise.resolve(),
    ]);

    // Create alerts for significant findings
    const criticalCount = webData?.summary?.critical ?? 0;
    const highCount = webData?.summary?.high ?? 0;
    
    if (criticalCount > 0) {
      await createAlert({
        type: 'vulnerability',
        severity: 'critical',
        title: `Critical vulnerabilities found on ${host}`,
        description: `Scan detected ${criticalCount} critical security issues requiring immediate attention`,
        sourceModule: 'autonomous_attack',
        target: host
      });
    }
    
    if (highCount > 0) {
      await createAlert({
        type: 'vulnerability',
        severity: 'high',
        title: `High-risk vulnerabilities on ${host}`,
        description: `${highCount} high severity issues detected during automated scan`,
        sourceModule: 'autonomous_attack',
        target: host
      });
    }

    await saveReport({
      module: 'autonomous_attack',
      title: `Domain Scan - ${host}`,
      summary: `Recon: ${reconCount} ports • Web: ${webCount} findings • CVE: ${vulnCount}`,
      findings: { target: host, recon: reconData, webapp: webData, vulnintel: vulnData },
      severityCounts: { critical: criticalCount, high: highCount, medium: webData?.summary?.medium ?? 0, low: webData?.summary?.low ?? 0 },
    });

    return { host, reconCount, webCount, vulnCount, reconData, webData, vulnData };
  };

  // Full audit (Recon + Web + API + Cloud + IAM + VulnIntel)
  const runFullAuditWorkflow = async (rawTarget: string) => {
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    updateLastAssistantMessage(`⏳ Full Audit: ${host}\n\n🔍 Phase 1/3: Reconnaissance & Web Security...`);
    toast({ title: "Full Audit Started", description: `Comprehensive security audit for ${host}` });

    // Phase 1: Recon + Web + VulnIntel
    const [reconScanId, webScanId, vulnScanId, apiScanId, cloudScanId, iamScanId] = await Promise.all([
      logScan({ module: 'recon', scanType: 'Full Audit - Reconnaissance', target: host }),
      logScan({ module: 'webapp', scanType: 'Full Audit - Web Security', target: url }),
      logScan({ module: 'vuln', scanType: 'Full Audit - Vulnerability Intel', target: host }),
      logScan({ module: 'api', scanType: 'Full Audit - API Security', target: url }),
      logScan({ module: 'cloud', scanType: 'Full Audit - Cloud Security', target: host }),
      logScan({ module: 'iam', scanType: 'Full Audit - IAM Security', target: host }),
    ]);

    const [reconResp, webResp, vulnResp] = await Promise.all([
      supabase.functions.invoke('recon', { body: { target: host } }),
      supabase.functions.invoke('webapp-scan', { body: { target: url } }),
      supabase.functions.invoke('vulnintel', { body: { query: host } }),
    ]);

    const reconData = reconResp.data || {};
    const webData = webResp.data || {};
    const vulnData = vulnResp.data || {};

    updateLastAssistantMessage(`⏳ Full Audit: ${host}\n\n✅ Phase 1: Recon + Web complete\n🔍 Phase 2/3: API + Cloud + IAM Security...`);

    // Phase 2: API + Cloud + IAM
    const [apiResp, cloudResp, iamResp] = await Promise.all([
      supabase.functions.invoke('api-security', { body: { target: url, scanType: 'comprehensive' } }),
      supabase.functions.invoke('cloud-security', { body: { provider: 'auto', target: host } }),
      supabase.functions.invoke('iam-security', { body: { target: host, scanType: 'full' } }),
    ]);

    const apiData = apiResp.data || {};
    const cloudData = cloudResp.data || {};
    const iamData = iamResp.data || {};

    updateLastAssistantMessage(`⏳ Full Audit: ${host}\n\n✅ Phase 1: Recon + Web complete\n✅ Phase 2: API + Cloud + IAM complete\n📊 Phase 3/3: Generating report...`);

    // Calculate findings
    const reconCount = Array.isArray(reconData?.ports) ? reconData.ports.length : 0;
    const webCount = Array.isArray(webData?.findings) ? webData.findings.length : 0;
    const vulnCount = vulnData?.count ?? 0;
    const apiCount = Array.isArray(apiData?.findings) ? apiData.findings.length : 0;
    const cloudCount = Array.isArray(cloudData?.findings) ? cloudData.findings.length : 0;
    const iamCount = Array.isArray(iamData?.findings) ? iamData.findings.length : 0;
    const totalFindings = reconCount + webCount + vulnCount + apiCount + cloudCount + iamCount;

    // Complete all scans
    await Promise.all([
      reconScanId ? completeScan(reconScanId, { status: 'completed', findingsCount: reconCount, report: reconData }) : Promise.resolve(),
      webScanId ? completeScan(webScanId, { status: 'completed', findingsCount: webCount, report: webData }) : Promise.resolve(),
      vulnScanId ? completeScan(vulnScanId, { status: 'completed', findingsCount: vulnCount, report: vulnData }) : Promise.resolve(),
      apiScanId ? completeScan(apiScanId, { status: 'completed', findingsCount: apiCount, report: apiData }) : Promise.resolve(),
      cloudScanId ? completeScan(cloudScanId, { status: 'completed', findingsCount: cloudCount, report: cloudData }) : Promise.resolve(),
      iamScanId ? completeScan(iamScanId, { status: 'completed', findingsCount: iamCount, report: iamData }) : Promise.resolve(),
    ]);

    // Save combined report
    await saveReport({
      module: 'full_audit',
      title: `Full Security Audit - ${host}`,
      summary: `Total: ${totalFindings} findings | Recon: ${reconCount} | Web: ${webCount} | API: ${apiCount} | Cloud: ${cloudCount} | IAM: ${iamCount} | CVE: ${vulnCount}`,
      findings: { target: host, recon: reconData, webapp: webData, api: apiData, cloud: cloudData, iam: iamData, vulnintel: vulnData },
      severityCounts: {
        critical: (webData?.summary?.critical ?? 0) + (apiData?.summary?.critical ?? 0) + (cloudData?.summary?.critical ?? 0),
        high: (webData?.summary?.high ?? 0) + (apiData?.summary?.high ?? 0) + (cloudData?.summary?.high ?? 0),
        medium: (webData?.summary?.medium ?? 0) + (apiData?.summary?.medium ?? 0),
        low: (webData?.summary?.low ?? 0),
      },
    });

    toast({ title: "Full Audit Complete", description: `${totalFindings} total findings across all modules` });
    return { host, totalFindings, reconCount, webCount, vulnCount, apiCount, cloudCount, iamCount };
  };

  // Red Team / Full VAPT automation
  const runRedTeamWorkflow = async (rawTarget: string) => {
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    updateLastAssistantMessage(`🔴 RED TEAM VAPT: ${host}\n\n⚔️ Phase 1/5: Reconnaissance & Attack Surface Mapping...`);
    toast({ title: "Red Team VAPT Started", description: `Full penetration testing for ${host}` });

    // Log all scans
    const scanIds = await Promise.all([
      logScan({ module: 'recon', scanType: 'Red Team - Recon', target: host }),
      logScan({ module: 'webapp', scanType: 'Red Team - Web Pentest', target: url }),
      logScan({ module: 'vuln', scanType: 'Red Team - Vuln Assessment', target: host }),
      logScan({ module: 'api', scanType: 'Red Team - API Pentest', target: url }),
      logScan({ module: 'cloud', scanType: 'Red Team - Cloud Audit', target: host }),
      logScan({ module: 'iam', scanType: 'Red Team - IAM Audit', target: host }),
    ]);

    // Phase 1: Recon
    const reconResp = await supabase.functions.invoke('recon', { body: { target: host } });
    const reconData = reconResp.data || {};
    
    updateLastAssistantMessage(`🔴 RED TEAM VAPT: ${host}\n\n✅ Phase 1: Recon complete (${reconData?.ports?.length || 0} ports)\n⚔️ Phase 2/5: Web Application Penetration Testing...`);

    // Phase 2: Web + VulnIntel
    const [webResp, vulnResp] = await Promise.all([
      supabase.functions.invoke('webapp-scan', { body: { target: url } }),
      supabase.functions.invoke('vulnintel', { body: { query: host } }),
    ]);
    const webData = webResp.data || {};
    const vulnData = vulnResp.data || {};

    updateLastAssistantMessage(`🔴 RED TEAM VAPT: ${host}\n\n✅ Phase 1: Recon complete\n✅ Phase 2: Web Pentest complete (${webData?.findings?.length || 0} findings)\n⚔️ Phase 3/5: API Security Testing...`);

    // Phase 3: API
    const apiResp = await supabase.functions.invoke('api-security', { body: { target: url, scanType: 'comprehensive' } });
    const apiData = apiResp.data || {};

    updateLastAssistantMessage(`🔴 RED TEAM VAPT: ${host}\n\n✅ Phase 1-3: Complete\n⚔️ Phase 4/5: Cloud & IAM Security Audit...`);

    // Phase 4: Cloud + IAM
    const [cloudResp, iamResp] = await Promise.all([
      supabase.functions.invoke('cloud-security', { body: { provider: 'auto', target: host } }),
      supabase.functions.invoke('iam-security', { body: { target: host, scanType: 'full' } }),
    ]);
    const cloudData = cloudResp.data || {};
    const iamData = iamResp.data || {};

    updateLastAssistantMessage(`🔴 RED TEAM VAPT: ${host}\n\n✅ Phase 1-4: Complete\n📊 Phase 5/5: Generating Pentest Report...`);

    // Phase 5: AI-powered attack synthesis
    const autonomousResp = await supabase.functions.invoke('autonomous-attack', {
      body: { target: host, objective: `Full VAPT based on findings: ${webData?.findings?.length || 0} web, ${apiData?.findings?.length || 0} API, ${cloudData?.findings?.length || 0} cloud vulnerabilities` }
    });
    const autonomousData = autonomousResp.data || {};

    // Calculate totals
    const reconCount = reconData?.ports?.length || 0;
    const webCount = webData?.findings?.length || 0;
    const vulnCount = vulnData?.count ?? 0;
    const apiCount = apiData?.findings?.length || 0;
    const cloudCount = cloudData?.findings?.length || 0;
    const iamCount = iamData?.findings?.length || 0;
    const attackSteps = autonomousData?.attack_chain?.length || 0;
    const totalFindings = reconCount + webCount + vulnCount + apiCount + cloudCount + iamCount;

    // Complete all scans
    const results = [reconData, webData, vulnData, apiData, cloudData, iamData];
    const counts = [reconCount, webCount, vulnCount, apiCount, cloudCount, iamCount];
    await Promise.all(scanIds.map((id, i) => id ? completeScan(id, { status: 'completed', findingsCount: counts[i], report: results[i] }) : Promise.resolve()));

    // Create alerts for critical findings
    const criticalCount = (webData?.summary?.critical ?? 0) + (apiData?.summary?.critical ?? 0) + (cloudData?.summary?.critical ?? 0);
    const highCount = (webData?.summary?.high ?? 0) + (apiData?.summary?.high ?? 0);

    if (criticalCount > 0 || totalFindings > 10) {
      await createAlert({
        type: 'red_team',
        severity: 'critical',
        title: `Red Team VAPT Complete: ${totalFindings} findings on ${host}`,
        description: `Critical: ${criticalCount} | High: ${highCount} | Attack paths: ${attackSteps}`,
        sourceModule: 'red_team',
        target: host
      });
    }

    // Save comprehensive report
    await saveReport({
      module: 'red_team',
      title: `Red Team VAPT Report - ${host}`,
      summary: `Total: ${totalFindings} findings | Attack Paths: ${attackSteps} | Critical vectors identified`,
      findings: { target: host, recon: reconData, webapp: webData, api: apiData, cloud: cloudData, iam: iamData, vulnintel: vulnData, autonomous: autonomousData },
      severityCounts: {
        critical: criticalCount,
        high: highCount,
        medium: (webData?.summary?.medium ?? 0),
        low: (webData?.summary?.low ?? 0),
      },
    });

    toast({ title: "Red Team VAPT Complete", description: `${totalFindings} findings, ${attackSteps} attack paths identified` });
    return { host, totalFindings, attackSteps, reconCount, webCount, vulnCount, apiCount, cloudCount, iamCount };
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const text = input.trim().toLowerCase();
    const originalText = input.trim();

    // Enhanced command detection with priority ordering
    const commandPatterns = [
      // Red Team / VAPT commands (highest priority)
      { regex: /(?:red\s*team|pentest|penetration\s*test|vapt|full\s*vapt)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'red_team', module: 'red_team' },
      { regex: /(?:hack|attack|exploit)\s+["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'red_team', module: 'red_team' },
      
      // Full audit commands
      { regex: /full\s*(?:security\s*)?audit\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'full_audit', module: 'workflow' },
      { regex: /(?:comprehensive|complete)\s+(?:security\s+)?(?:scan|audit|test)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'full_audit', module: 'workflow' },
      { regex: /audit\s+(?:all|everything)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'full_audit', module: 'workflow' },
      
      // Domain scan commands
      { regex: /^scan\s+(?:domain\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?$/i, action: 'domain_scan', module: 'workflow' },
      { regex: /scan\s+(?:this\s+)?(?:domain|website|site|target)\s+["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'domain_scan', module: 'workflow' },
      
      // Specific module commands
      { regex: /(?:api|rest|graphql)\s+(?:security\s+)?(?:scan|test|audit)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'api_scan', module: 'api' },
      { regex: /cloud\s+(?:security\s+)?(?:scan|audit|check)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'cloud_scan', module: 'cloud' },
      { regex: /(?:iam|identity|auth)\s+(?:security\s+)?(?:scan|audit|check)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'iam_scan', module: 'iam' },
      { regex: /(?:recon|reconnaissance|discover)\s+["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'recon', module: 'recon' },
      { regex: /(?:web|webapp|website)\s+(?:security\s+)?(?:scan|test|audit)\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'web_scan', module: 'webapp' },
      { regex: /(?:vuln|vulnerability|cve)\s+(?:scan|check|search)\s+(?:for\s+)?["']?(.+?)["']?$/i, action: 'vuln_scan', module: 'vulnintel' },
      { regex: /(?:find|search|check)\s+(?:for\s+)?(?:vulns?|vulnerabilities?|cves?)\s+(?:in|on|for)\s+["']?(.+?)["']?$/i, action: 'vuln_scan', module: 'vulnintel' },
      
      // Port/network scans
      { regex: /(?:port|network)\s+scan\s+(?:on\s+)?["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'recon', module: 'recon' },
      
      // Generic target extraction (lowest priority)
      { regex: /(?:scan|test|check|audit)\s+["']?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})["']?/i, action: 'domain_scan', module: 'workflow' },
    ];

    let metadata: Message['metadata'] = undefined;

    for (const pattern of commandPatterns) {
      const match = originalText.match(pattern.regex);
      if (!match) continue;

      const target = match[1].trim();
      metadata = { command: pattern.action, target, action: pattern.action };

      setMessages((prev) => [
        ...prev,
        { role: "user", content: originalText, metadata },
        { role: "assistant", content: `⏳ Initiating ${pattern.action.replace('_', ' ')} on ${target}...` }
      ]);
      setInput("");
      setLoading(true);

      try {
        if (pattern.action === 'red_team') {
          const result = await runRedTeamWorkflow(target);
          updateLastAssistantMessage(`🔴 RED TEAM VAPT COMPLETE: ${result.host}\n\n📊 FINDINGS SUMMARY:\n• Reconnaissance: ${result.reconCount} open ports\n• Web Security: ${result.webCount} vulnerabilities\n• API Security: ${result.apiCount} issues\n• Cloud Security: ${result.cloudCount} misconfigurations\n• IAM Security: ${result.iamCount} weaknesses\n• Known CVEs: ${result.vulnCount}\n• Attack Paths: ${result.attackSteps}\n\n🎯 Total: ${result.totalFindings} findings\n\n✅ Full report saved. Check Reports tab for details.`);
        } else if (pattern.action === 'full_audit') {
          const result = await runFullAuditWorkflow(target);
          updateLastAssistantMessage(`✅ FULL SECURITY AUDIT COMPLETE: ${result.host}\n\n📊 FINDINGS:\n• Recon: ${result.reconCount} ports\n• Web: ${result.webCount} issues\n• API: ${result.apiCount} vulnerabilities\n• Cloud: ${result.cloudCount} misconfigs\n• IAM: ${result.iamCount} weaknesses\n• CVEs: ${result.vulnCount}\n\n🎯 Total: ${result.totalFindings} findings\n\n✅ Combined report saved.`);
        } else if (pattern.action === 'domain_scan') {
          const result = await runDomainScanWorkflow(target);
          updateLastAssistantMessage(`✅ SCAN COMPLETE: ${result.host}\n\n• Recon: ${result.reconCount} open ports\n• Web: ${result.webCount} findings\n• CVEs: ${result.vulnCount}\n\n✅ Report saved.`);
        } else if (pattern.action === 'api_scan') {
          const scanId = await logScan({ module: 'api', scanType: 'Chat-triggered API Security', target });
          const { data, error } = await supabase.functions.invoke('api-security', { body: { target: normalizeUrl(target), scanType: 'comprehensive' } });
          if (error) throw error;
          const count = data?.findings?.length || 0;
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: count, report: data });
          updateLastAssistantMessage(`✅ API Security Scan Complete: ${target}\n\nFindings: ${count}\n${(data?.findings || []).slice(0, 5).map((f: any) => `• [${f.severity}] ${f.title}`).join('\n')}`);
        } else if (pattern.action === 'cloud_scan') {
          const scanId = await logScan({ module: 'cloud', scanType: 'Chat-triggered Cloud Security', target });
          const { data, error } = await supabase.functions.invoke('cloud-security', { body: { provider: 'auto', target } });
          if (error) throw error;
          const count = data?.findings?.length || 0;
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: count, report: data });
          updateLastAssistantMessage(`✅ Cloud Security Scan Complete: ${target}\n\nFindings: ${count}\n${(data?.findings || []).slice(0, 5).map((f: any) => `• [${f.severity}] ${f.title}`).join('\n')}`);
        } else if (pattern.action === 'iam_scan') {
          const scanId = await logScan({ module: 'iam', scanType: 'Chat-triggered IAM Security', target });
          const { data, error } = await supabase.functions.invoke('iam-security', { body: { target, scanType: 'full' } });
          if (error) throw error;
          const count = data?.findings?.length || 0;
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: count, report: data });
          updateLastAssistantMessage(`✅ IAM Security Scan Complete: ${target}\n\nFindings: ${count}\n${(data?.findings || []).slice(0, 5).map((f: any) => `• [${f.severity}] ${f.title}`).join('\n')}`);
        } else if (pattern.action === 'recon') {
          const host = normalizeHost(target);
          const scanId = await logScan({ module: 'recon', scanType: 'Chat-triggered Recon', target: host });
          const { data, error } = await supabase.functions.invoke('recon', { body: { target: host } });
          if (error) throw error;
          const ports = data?.ports || [];
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: ports.length, report: data });
          updateLastAssistantMessage(`✅ Recon Complete: ${host}\n\nIP: ${data?.ip || 'N/A'}\nOpen Ports: ${ports.length}\n${ports.slice(0, 10).map((p: any) => `• ${p.port} ${p.service || ''}`).join('\n')}`);
        } else if (pattern.action === 'web_scan') {
          const url = normalizeUrl(target);
          const scanId = await logScan({ module: 'webapp', scanType: 'Chat-triggered Web Scan', target: url });
          const { data, error } = await supabase.functions.invoke('webapp-scan', { body: { target: url } });
          if (error) throw error;
          const findings = data?.findings || [];
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: findings.length, report: data });
          updateLastAssistantMessage(`✅ Web Security Scan Complete: ${url}\n\nFindings: ${findings.length}\n${findings.slice(0, 6).map((f: any) => `• [${f.severity}] ${f.title}`).join('\n')}`);
        } else if (pattern.action === 'vuln_scan') {
          const scanId = await logScan({ module: 'vuln', scanType: 'Chat-triggered Vuln Intel', target });
          const { data, error } = await supabase.functions.invoke('vulnintel', { body: { query: target } });
          if (error) throw error;
          const count = data?.count ?? 0;
          if (scanId) await completeScan(scanId, { status: 'completed', findingsCount: count, report: data });
          updateLastAssistantMessage(`✅ Vulnerability Intel Complete: ${target}\n\nCVEs Found: ${count}\n${(data?.vulnerabilities || []).slice(0, 5).map((v: any) => `• ${v.cve} (${v.severity})`).join('\n')}`);
        }
      } catch (error: any) {
        console.error('Command execution error:', error);
        toast({ title: "Command failed", description: error?.message || "Failed to execute", variant: "destructive" });
        updateLastAssistantMessage(`❌ Error: ${error?.message || 'Command failed'}`);
      } finally {
        setLoading(false);
      }
      return;
    }

    // Regular chat if no command detected
    const userMsg: Message = { role: "user", content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    let assistantSoFar = "";
    const upsertAssistant = (next: string) => {
      assistantSoFar += next;
      setMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last?.role === "assistant") {
          return prev.map((m, i) => (i === prev.length - 1 ? { ...m, content: assistantSoFar } : m));
        }
        return [...prev, { role: "assistant", content: assistantSoFar }];
      });
    };

    try {
      await streamChat({
        messages: [...messages, userMsg],
        onDelta: upsertAssistant,
        onDone: () => setLoading(false),
      });
    } catch (e: any) {
      console.error(e);
      setLoading(false);

      if (e instanceof StreamError && e.code === 'rate_limit') {
        toast({ title: "Rate limited", description: "Too many AI requests. Please retry in a moment.", variant: "destructive" });
      } else if (e instanceof StreamError && e.code === 'payment_required') {
        toast({ title: "AI credits exhausted", description: "Add credits to continue using AI features.", variant: "destructive" });
      } else {
        toast({ title: "AI unavailable", description: "Chat is temporarily unavailable.", variant: "destructive" });
      }

      setMessages((prev) => [...prev, { role: "assistant", content: "Sorry, the AI is unavailable right now." }]);
    }
  };

  return (
    <Card className="h-full flex flex-col bg-card/50 backdrop-blur-sm border-cyber-purple/30 overflow-hidden">
      <div className="p-4 border-b border-border/50 flex items-center gap-2 flex-shrink-0">
        <Sparkles className="h-5 w-5 text-cyber-purple" />
        <h3 className="font-semibold font-mono">AI Control Interface</h3>
      </div>

      <div ref={scrollContainerRef} className="flex-1 overflow-y-auto p-4">
        <div className="space-y-4">
          {messages.map((message, i) => (
            <div key={i} className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[80%] p-3 rounded-lg ${
                  message.role === "user"
                    ? "bg-cyber-cyan/10 text-foreground border border-cyber-cyan/30"
                    : "bg-cyber-purple/10 text-foreground border border-cyber-purple/30"
                }`}
              >
                <p className="text-sm font-mono whitespace-pre-wrap">{message.content}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="p-4 border-t border-border/50 flex-shrink-0">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder='Try: scan domain "example.com"'
            className="font-mono bg-background/50"
            disabled={loading}
          />
          <Button onClick={handleSend} size="icon" className="bg-cyber-purple hover:bg-cyber-purple/80" disabled={loading}>
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </Card>
  );
};
