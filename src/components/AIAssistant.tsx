import { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Send, Sparkles } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

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
  if (!resp.ok || !resp.body) {
    throw new Error(`Failed to start stream (${resp.status})`);
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
      } catch { /* ignore */ }
    }
  }

  onDone();
}

export const AIAssistant = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "OmniSec AI Assistant online. Ready to assist with security operations. How may I help you?",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    
    // Parse command from user input
    const commandPatterns = [
      { regex: /scan\s+network\s+(.+)/i, action: 'scan_network', module: 'recon' },
      { regex: /scan\s+ports?\s+(?:on|of)?\s*(.+)/i, action: 'port_scan', module: 'recon' },
      { regex: /find\s+vulnerabilities?\s+(?:in|on)\s+(.+)/i, action: 'vuln_scan', module: 'vulnintel' },
      { regex: /check\s+(?:for\s+)?(?:sql\s+injection|xss|vulnerabilities)\s+(?:on|in)\s+(.+)/i, action: 'web_scan', module: 'webapp' },
      { regex: /enumerate\s+(?:subdomains?|directories?|services?)\s+(?:of|on|for)\s+(.+)/i, action: 'enumerate', module: 'recon' },
      { regex: /exploit\s+(.+)/i, action: 'exploit', module: 'redteam' },
      { regex: /analyze\s+(.+)/i, action: 'analyze', module: 'analysis' },
      { regex: /perform\s+(?:full\s+)?(?:security\s+)?(?:audit|scan)\s+(?:on\s+)?(.+)/i, action: 'full_audit', module: 'all' }
    ];
    
    let metadata: Message['metadata'] = undefined;
    let autoExecute = false;
    
    for (const pattern of commandPatterns) {
      const match = input.match(pattern.regex);
      if (match) {
        metadata = {
          command: pattern.action,
          target: match[1].trim(),
          action: pattern.action
        };
        autoExecute = true;
        
        // Auto-execute the command
        const executionMsg: Message = {
          role: "assistant",
          content: `🔍 **Command Detected**: ${pattern.action}\n🎯 **Target**: ${match[1].trim()}\n⚙️ **Module**: ${pattern.module}\n\n⏳ Executing security operation...`
        };
        setMessages((prev) => [...prev, { role: "user", content: input, metadata }, executionMsg]);
        setInput("");
        setLoading(true);
        
        // Execute based on module
        try {
          let result = '';
          if (pattern.module === 'recon') {
            const { data, error } = await supabase.functions.invoke('recon', {
              body: { target: match[1].trim() }
            });
            if (error) throw error;
            result = `✅ **Recon Complete**\n\n**Host**: ${data.host}\n**IP**: ${data.ip}\n**Status**: ${data.status}\n\n**Open Ports**:\n${data.ports.map((p: any) => `- Port ${p.port}: ${p.service} (${p.product || 'Unknown'})`).join('\n')}`;
          } else if (pattern.module === 'vulnintel') {
            const { data, error } = await supabase.functions.invoke('vulnintel', {
              body: { query: match[1].trim() }
            });
            if (error) throw error;
            result = `✅ **Vulnerability Scan Complete**\n\n**Found**: ${data.count} vulnerabilities\n\n${data.vulnerabilities.slice(0, 3).map((v: any) => `**${v.id}**\n- Severity: ${v.severity}\n- CVSS: ${v.cvss}\n- ${v.description.substring(0, 100)}...`).join('\n\n')}`;
          } else {
            // Use VAPT assistant for other commands
            const { data, error } = await supabase.functions.invoke('vapt-assistant', {
              body: { 
                prompt: `Execute command: ${pattern.action} on target: ${match[1].trim()}. Provide a detailed security assessment report.`,
                mode: 'security'
              }
            });
            if (error) throw error;
            result = `✅ **Analysis Complete**\n\n${data.answer}`;
          }
          
          setMessages((prev) => [...prev, { role: "assistant", content: result }]);
        } catch (error: any) {
          console.error('Command execution error:', error);
          setMessages((prev) => [...prev, { 
            role: "assistant", 
            content: `❌ **Error**: ${error.message || 'Failed to execute command'}\n\nPlease check your API keys in Settings or try again.` 
          }]);
        } finally {
          setLoading(false);
        }
        return;
      }
    }
    
    // Regular chat if no command detected
    const userMsg: Message = { role: "user", content: input };
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
    } catch (e) {
      console.error(e);
      setLoading(false);
      setMessages((prev) => [...prev, { role: "assistant", content: "Sorry, the AI is unavailable right now." }]);
    }
  };

  return (
    <Card className="h-full flex flex-col bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <div className="p-4 border-b border-border/50 flex items-center gap-2">
        <Sparkles className="h-5 w-5 text-cyber-purple" />
        <h3 className="font-semibold font-mono">AI Control Interface</h3>
      </div>

      <ScrollArea className="flex-1 p-4">
        <div className="space-y-4">
          {messages.map((message, i) => (
            <div
              key={i}
              className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
            >
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
          <div ref={messagesEndRef} />
        </div>
      </ScrollArea>

      <div className="p-4 border-t border-border/50">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Ask anything (threat intel, recon steps, CVEs, etc.)"
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
