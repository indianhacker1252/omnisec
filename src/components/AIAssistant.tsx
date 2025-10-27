import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Send, Sparkles } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
}

export const AIAssistant = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "OmniSec AI Assistant online. Ready to assist with security operations. How may I help you?",
    },
  ]);
  const [input, setInput] = useState("");

  const handleSend = () => {
    if (!input.trim()) return;

    const newMessage: Message = { role: "user", content: input };
    setMessages((prev) => [...prev, newMessage]);
    setInput("");

    // Simulate AI response
    setTimeout(() => {
      const responses = [
        "Analyzing your request... Standing by for execution.",
        "Scanning target network. 245 hosts discovered.",
        "Vulnerability assessment initiated. Running Nuclei templates.",
        "Red team simulation configured. Lab mode active.",
        "Threat intelligence correlation complete. 12 CVEs matched.",
      ];
      const response: Message = {
        role: "assistant",
        content: responses[Math.floor(Math.random() * responses.length)],
      };
      setMessages((prev) => [...prev, response]);
    }, 1000);
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
              className={`flex ${
                message.role === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`max-w-[80%] p-3 rounded-lg ${
                  message.role === "user"
                    ? "bg-cyber-cyan/10 text-foreground border border-cyber-cyan/30"
                    : "bg-cyber-purple/10 text-foreground border border-cyber-purple/30"
                }`}
              >
                <p className="text-sm font-mono">{message.content}</p>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>

      <div className="p-4 border-t border-border/50">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === "Enter" && handleSend()}
            placeholder="Enter command or query..."
            className="font-mono bg-background/50"
          />
          <Button onClick={handleSend} size="icon" className="bg-cyber-purple hover:bg-cyber-purple/80">
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </Card>
  );
};
