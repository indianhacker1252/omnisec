import { useState, useRef, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Send, Sparkles, History, Plus, Trash2, Save } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import ReactMarkdown from "react-markdown";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface Conversation {
  id: string;
  title: string;
  messages: Message[];
  updated_at: string;
}

const CHAT_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/chat`;

type StreamErrorCode = "rate_limit" | "payment_required" | "http_error";
class StreamError extends Error {
  code: StreamErrorCode;
  constructor(message: string, code: StreamErrorCode) {
    super(message);
    this.code = code;
  }
}

async function streamChat({
  messages,
  onDelta,
  onDone,
  conversationId,
}: {
  messages: Message[];
  onDelta: (deltaText: string) => void;
  onDone: () => void;
  conversationId?: string;
}) {
  const { data: { session } } = await supabase.auth.getSession();
  const accessToken = session?.access_token;
  if (!accessToken) throw new StreamError("Unauthorized", "http_error");

  const resp = await fetch(CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      apikey: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
    },
    body: JSON.stringify({ messages, conversationId, saveHistory: !!conversationId }),
  });

  if (!resp.ok) {
    if (resp.status === 429) throw new StreamError("Rate limited", "rate_limit");
    if (resp.status === 402) throw new StreamError("AI credits exhausted", "payment_required");
    throw new StreamError(`Chat failed (${resp.status})`, "http_error");
  }
  if (!resp.body) throw new StreamError("No response body", "http_error");

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
      if (jsonStr === "[DONE]") { streamDone = true; break; }
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
      } catch { /* partial */ }
    }
  }
  onDone();
}

const WELCOME_MSG: Message = {
  role: "assistant",
  content: `**OmniSec™ AI Assistant** — Elite VAPT Intelligence\n\nI can **directly execute** security operations:\n\n🔴 **"scan testphp.vulnweb.com"** — Full autonomous VAPT\n🔍 **"find subdomains of example.com"** — Subdomain enumeration\n🌐 **"check CVEs for Apache 2.4"** — Vulnerability research\n⚡ **"generate XSS payloads for PHP"** — Payload generation\n📡 **"discover endpoints on target.com"** — Endpoint discovery\n\nI use AI tool-calling to automatically invoke the right scan modules. Just describe what you need!`,
};

export const AIAssistant = () => {
  const { toast } = useToast();
  const [messages, setMessages] = useState<Message[]>([WELCOME_MSG]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);

  // Load conversation history
  const loadHistory = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;
    const { data } = await supabase
      .from("chat_conversations")
      .select("*")
      .order("updated_at", { ascending: false })
      .limit(50);
    if (data) {
      setConversations(data.map((c: any) => ({
        id: c.id,
        title: c.title,
        messages: (c.messages as any[]) || [],
        updated_at: c.updated_at,
      })));
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const saveConversation = async (msgs: Message[], title?: string) => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return null;

    const autoTitle = title || msgs.find(m => m.role === "user")?.content.slice(0, 60) || "New Conversation";

    if (activeConversationId) {
      await supabase.from("chat_conversations").update({
        messages: msgs as any,
        title: autoTitle,
        updated_at: new Date().toISOString(),
      }).eq("id", activeConversationId);
      return activeConversationId;
    } else {
      const { data } = await supabase.from("chat_conversations").insert({
        user_id: session.user.id,
        title: autoTitle,
        messages: msgs as any,
      }).select().single();
      if (data) {
        setActiveConversationId(data.id);
        return data.id;
      }
    }
    return null;
  };

  const loadConversation = (conv: Conversation) => {
    setMessages(conv.messages.length > 0 ? conv.messages : [WELCOME_MSG]);
    setActiveConversationId(conv.id);
    setShowHistory(false);
  };

  const startNewConversation = () => {
    setMessages([WELCOME_MSG]);
    setActiveConversationId(null);
    setShowHistory(false);
  };

  const deleteConversation = async (id: string) => {
    await supabase.from("chat_conversations").delete().eq("id", id);
    setConversations(prev => prev.filter(c => c.id !== id));
    if (activeConversationId === id) startNewConversation();
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = { role: "user", content: input.trim() };
    const newMessages = [...messages.filter(m => m !== WELCOME_MSG || messages.length > 1), userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    let assistantSoFar = "";
    const upsert = (chunk: string) => {
      assistantSoFar += chunk;
      setMessages(prev => {
        const last = prev[prev.length - 1];
        if (last?.role === "assistant" && prev.length > 1 && prev[prev.length - 2]?.role === "user") {
          return prev.map((m, i) => (i === prev.length - 1 ? { ...m, content: assistantSoFar } : m));
        }
        return [...prev, { role: "assistant", content: assistantSoFar }];
      });
    };

    try {
      // Filter out the welcome message for API calls
      const apiMessages = newMessages.filter(m => m !== WELCOME_MSG);

      await streamChat({
        messages: apiMessages,
        onDelta: upsert,
        onDone: async () => {
          setLoading(false);
          // Auto-save after every exchange
          const finalMessages = [...apiMessages, { role: "assistant" as const, content: assistantSoFar }];
          await saveConversation(finalMessages);
          loadHistory();
        },
        conversationId: activeConversationId || undefined,
      });
    } catch (e: any) {
      console.error(e);
      setLoading(false);
      if (e instanceof StreamError) {
        if (e.code === "rate_limit") toast({ title: "Rate limited", description: "Please retry in a moment.", variant: "destructive" });
        else if (e.code === "payment_required") toast({ title: "Credits exhausted", description: "Add credits to continue.", variant: "destructive" });
        else toast({ title: "AI unavailable", description: e.message, variant: "destructive" });
      }
      setMessages(prev => [...prev, { role: "assistant", content: "⚠️ Error connecting to AI. Please try again." }]);
    }
  };

  if (showHistory) {
    return (
      <Card className="h-full flex flex-col bg-card/50 backdrop-blur-sm border-cyber-purple/30 overflow-hidden">
        <div className="p-4 border-b border-border/50 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-cyber-purple" />
            <h3 className="font-semibold font-mono">Chat History</h3>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={startNewConversation}>
              <Plus className="h-4 w-4 mr-1" /> New
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setShowHistory(false)}>Back</Button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {conversations.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-8">No saved conversations yet.</p>
          )}
          {conversations.map(conv => (
            <div key={conv.id}
              className="p-3 rounded-lg border border-border/50 hover:border-cyber-purple/50 cursor-pointer flex justify-between items-start group"
              onClick={() => loadConversation(conv)}
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{conv.title}</p>
                <p className="text-xs text-muted-foreground">{new Date(conv.updated_at).toLocaleString()} • {conv.messages.length} msgs</p>
              </div>
              <Button size="icon" variant="ghost" className="h-6 w-6 opacity-0 group-hover:opacity-100"
                onClick={(e) => { e.stopPropagation(); deleteConversation(conv.id); }}>
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      </Card>
    );
  }

  return (
    <Card className="h-full flex flex-col bg-card/50 backdrop-blur-sm border-cyber-purple/30 overflow-hidden">
      <div className="p-4 border-b border-border/50 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-cyber-purple" />
          <h3 className="font-semibold font-mono text-sm">OmniSec AI {activeConversationId ? "💬" : ""}</h3>
        </div>
        <div className="flex gap-1">
          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={startNewConversation} title="New chat">
            <Plus className="h-4 w-4" />
          </Button>
          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => { setShowHistory(true); loadHistory(); }} title="History">
            <History className="h-4 w-4" />
          </Button>
          <Button size="icon" variant="ghost" className="h-7 w-7"
            onClick={() => { saveConversation(messages); toast({ title: "Chat saved" }); loadHistory(); }}
            title="Save chat">
            <Save className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4">
        <div className="space-y-4">
          {messages.map((message, i) => (
            <div key={i} className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}>
              <div className={`max-w-[85%] p-3 rounded-lg ${
                message.role === "user"
                  ? "bg-cyber-cyan/10 text-foreground border border-cyber-cyan/30"
                  : "bg-cyber-purple/10 text-foreground border border-cyber-purple/30"
              }`}>
                <div className="text-sm font-mono prose prose-sm prose-invert max-w-none [&_pre]:bg-background/50 [&_pre]:p-2 [&_pre]:rounded [&_code]:text-cyber-cyan [&_strong]:text-cyber-purple [&_h1]:text-base [&_h2]:text-sm [&_h3]:text-sm [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0.5 [&_p]:my-1">
                  <ReactMarkdown>{message.content}</ReactMarkdown>
                </div>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-cyber-purple/10 border border-cyber-purple/30 p-3 rounded-lg">
                <div className="flex items-center gap-2 text-sm text-muted-foreground font-mono">
                  <div className="animate-pulse">🔄</div>
                  <span>Processing... (AI may be executing security tools)</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="p-4 border-t border-border/50 flex-shrink-0">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Scan testphp.vulnweb.com, find CVEs for Apache..."
            className="font-mono bg-background/50 text-sm"
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
