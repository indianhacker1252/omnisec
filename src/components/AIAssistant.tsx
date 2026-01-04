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
  const { logScan, completeScan, saveReport } = useScanHistory();

  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "OmniSec AI Assistant online. You can say: ‘scan domain example.com’ to start an automated scan.",
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

  const runDomainScanWorkflow = async (rawTarget: string) => {
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    toast({
      title: "Automated scan started",
      description: `Running Recon + WebApp + VulnIntel for ${host}`,
    });

    // Create scan_history entries so the module History tabs reflect the run
    const [reconScanId, webScanId, vulnScanId] = await Promise.all([
      logScan({ module: 'recon', scanType: 'Chat-triggered Reconnaissance', target: host }),
      logScan({ module: 'webapp', scanType: 'Chat-triggered Web Application Security Scan', target: url }),
      logScan({ module: 'vuln', scanType: 'Chat-triggered Vulnerability Intelligence', target: host }),
    ]);

    // Execute real scans in parallel
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

    const reconFindingsCount = Array.isArray(reconData?.ports) ? reconData.ports.length : 0;
    const webFindingsCount = Array.isArray(webData?.findings) ? webData.findings.length : 0;
    const vulnFindingsCount = typeof vulnData?.count === 'number' ? vulnData.count : (Array.isArray(vulnData?.vulnerabilities) ? vulnData.vulnerabilities.length : 0);

    await Promise.all([
      reconScanId ? completeScan(reconScanId, { status: 'completed', findingsCount: reconFindingsCount, report: reconData }) : Promise.resolve(),
      webScanId ? completeScan(webScanId, { status: 'completed', findingsCount: webFindingsCount, report: webData }) : Promise.resolve(),
      vulnScanId ? completeScan(vulnScanId, { status: 'completed', findingsCount: vulnFindingsCount, report: vulnData }) : Promise.resolve(),
    ]);

    // Save a unified report record under a dedicated module name to make it easy to find
    await saveReport({
      module: 'autonomous_attack',
      title: `Automated Domain Scan - ${host}`,
      summary: `Recon ports: ${reconFindingsCount} • Web findings: ${webFindingsCount} • CVEs: ${vulnFindingsCount}`,
      findings: {
        target: host,
        recon: reconData,
        webapp: webData,
        vulnintel: vulnData,
      },
      severityCounts: {
        critical: (webData?.summary?.critical ?? 0),
        high: (webData?.summary?.high ?? 0),
        medium: (webData?.summary?.medium ?? 0),
        low: (webData?.summary?.low ?? 0),
      },
    });

    appendAssistantMessage(
      [
        `✅ Automated scan completed for ${host}`,
        ``,
        `Recon: ${reconFindingsCount} open ports (source: ${reconData?.source || 'unknown'})`,
        `WebApp: ${webFindingsCount} findings`,
        `VulnIntel: ${vulnFindingsCount} CVEs matched`,
        ``,
        `Reports were saved and will appear under the relevant module “History/Reports” tabs.`,
      ].join("\n")
    );

    toast({
      title: "Automated scan complete",
      description: `Recon ${reconFindingsCount} • Web ${webFindingsCount} • CVE ${vulnFindingsCount}`,
    });
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const text = input.trim();

    // Command patterns (chat-triggered automation)
    const commandPatterns = [
      { regex: /^(?:scan|audit)\s+(?:this\s+)?domain\s+"?([^"\n]+)"?$/i, action: 'domain_scan', module: 'workflow' },
      { regex: /^scan\s+"?([^"\n]+)"?$/i, action: 'domain_scan', module: 'workflow' },
      { regex: /scan\s+network\s+(.+)/i, action: 'scan_network', module: 'recon' },
      { regex: /scan\s+ports?\s+(?:on|of)?\s*(.+)/i, action: 'port_scan', module: 'recon' },
      { regex: /find\s+vulnerabilities?\s+(?:in|on)\s+(.+)/i, action: 'vuln_scan', module: 'vulnintel' },
      { regex: /check\s+(?:for\s+)?(?:sql\s+injection|xss|vulnerabilities)\s+(?:on|in)\s+(.+)/i, action: 'web_scan', module: 'webapp' },
      { regex: /enumerate\s+(?:subdomains?|directories?|services?)\s+(?:of|on|for)\s+(.+)/i, action: 'enumerate', module: 'recon' },
      { regex: /analyze\s+(.+)/i, action: 'analyze', module: 'analysis' },
      { regex: /perform\s+(?:full\s+)?(?:security\s+)?(?:audit|scan)\s+(?:on\s+)?(.+)/i, action: 'full_audit', module: 'workflow' },
    ];

    let metadata: Message['metadata'] = undefined;

    for (const pattern of commandPatterns) {
      const match = text.match(pattern.regex);
      if (!match) continue;

      metadata = {
        command: pattern.action,
        target: match[1].trim(),
        action: pattern.action,
      };

      setMessages((prev) => [
        ...prev,
        { role: "user", content: text, metadata },
        {
          role: "assistant",
          content: `⏳ Running: ${pattern.action} on ${match[1].trim()}... (authorized targets only)`
        }
      ]);
      setInput("");
      setLoading(true);

      try {
        if (pattern.action === 'domain_scan' || pattern.action === 'full_audit') {
          await runDomainScanWorkflow(match[1].trim());
        } else if (pattern.module === 'recon') {
          const host = normalizeHost(match[1].trim());
          const scanId = await logScan({ module: 'recon', scanType: 'Chat-triggered Reconnaissance', target: host });
          const { data, error } = await supabase.functions.invoke('recon', { body: { target: host } });
          if (error) throw error;

          const ports = (data?.ports || []).map((p: any) => `- ${p.port} ${p.service || ''} ${p.product ? `(${p.product})` : ''}`.trim());
          const resultText = `✅ Recon Complete\nHost: ${data.host}\nIP: ${data.ip}\nOpen ports: ${ports.length || 0}\n${ports.slice(0, 12).join("\n")}${ports.length > 12 ? "\n..." : ""}`;

          if (scanId) {
            await completeScan(scanId, { status: 'completed', findingsCount: ports.length, report: data });
          }
          appendAssistantMessage(resultText);
        } else if (pattern.module === 'vulnintel') {
          const q = match[1].trim();
          const scanId = await logScan({ module: 'vuln', scanType: 'Chat-triggered Vulnerability Intelligence', target: q });
          const { data, error } = await supabase.functions.invoke('vulnintel', { body: { query: q } });
          if (error) throw error;

          const top = (data.vulnerabilities || []).slice(0, 5).map((v: any) => `- ${v.cve} (${v.severity}${v.cvss ? `, CVSS ${v.cvss}` : ''})`);
          const resultText = `✅ VulnIntel Complete\nQuery: ${q}\nFound: ${data.count}\n${top.join("\n")}${data.count > 5 ? "\n..." : ""}`;

          if (scanId) {
            await completeScan(scanId, { status: 'completed', findingsCount: data.count || 0, report: data });
          }

          appendAssistantMessage(resultText);
        } else if (pattern.module === 'webapp') {
          const url = normalizeUrl(match[1].trim());
          const scanId = await logScan({ module: 'webapp', scanType: 'Chat-triggered Web Application Security Scan', target: url });
          const { data, error } = await supabase.functions.invoke('webapp-scan', { body: { target: url } });
          if (error) throw error;

          const findings = (data.findings || []) as any[];
          const counts = data.summary || {};
          const top = findings.slice(0, 6).map((f: any) => `- [${f.severity}] ${f.title}`);
          const resultText = `✅ WebApp Scan Complete\nTarget: ${url}\nFindings: ${findings.length}\nCritical: ${counts.critical || 0} • High: ${counts.high || 0} • Medium: ${counts.medium || 0} • Low: ${counts.low || 0}\n${top.join("\n")}${findings.length > 6 ? "\n..." : ""}`;

          if (scanId) {
            await completeScan(scanId, { status: 'completed', findingsCount: findings.length, report: data });
          }

          appendAssistantMessage(resultText);
        } else {
          // Fall back to AI explanation (no automatic scanning)
          const { data, error } = await supabase.functions.invoke('vapt-assistant', {
            body: {
              prompt: `User requested: ${text}. Provide safe, authorized-testing-only guidance and point them to the correct module to run it.`,
              mode: 'security'
            }
          });
          if (error) throw error;
          appendAssistantMessage(`✅ Guidance\n\n${data.answer}`);
        }
      } catch (error: any) {
        console.error('Command execution error:', error);
        toast({
          title: "Command failed",
          description: error?.message || "Failed to execute command",
          variant: "destructive",
        });
        appendAssistantMessage(`❌ Error: ${error?.message || 'Failed to execute command'}`);
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
