/**
 * OmniSec™ Red Team Operations Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Advanced Offensive Security Platform
 */

import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Terminal, Target, Users, Activity, Globe, Lock, Zap, ArrowLeft, Download, Key, Shield, Code } from "lucide-react";

const RedTeamModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [selectedPayload, setSelectedPayload] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("4444");
  const [generating, setGenerating] = useState(false);
  const [generatedPayload, setGeneratedPayload] = useState<any>(null);

  const generatePayload = async (type: string) => {
    if (type === "reverse-shell" && !target.trim()) {
      toast({ title: "Error", description: "Enter target IP for reverse shell", variant: "destructive" });
      return;
    }
    setGenerating(true);
    setSelectedPayload(type);
    try {
      const { data, error } = await supabase.functions.invoke('payload-generator', {
        body: { type, target, port: parseInt(port), options: {} }
      });
      if (error) throw error;
      if (data.success) {
        setGeneratedPayload(data);
        toast({ title: "Payload Generated", description: "Ready to use" });
      }
    } catch (error: any) {
      toast({ title: "Failed", description: error.message, variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  };

  const payloadTypes = [
    { name: "Reverse Shell", icon: Terminal, description: "Netcat, Bash, PowerShell", category: "shells" },
    { name: "Web Shells", icon: Globe, description: "PHP, ASP, JSP shells", category: "webshells" },
    { name: "Privilege Escalation", icon: Lock, description: "Linux & Windows exploits", category: "privesc" },
    { name: "Persistence", icon: Activity, description: "Registry, Cron, Services", category: "persistence" },
    { name: "Lateral Movement", icon: Users, description: "PsExec, WMI, RDP", category: "lateral" },
    { name: "Data Exfiltration", icon: Download, description: "DNS, ICMP, HTTPS", category: "exfil" },
    { name: "Credential Dumping", icon: Key, description: "Mimikatz, SAM, LSASS", category: "creds" },
    { name: "Obfuscation", icon: Shield, description: "Encoding, Encryption", category: "obfuscation" },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <Button variant="ghost" onClick={() => navigate("/")} className="mb-6 gap-2">
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Target className="h-8 w-8 text-cyber-red" />
            <h1 className="text-3xl font-bold font-mono">Red Team Operations</h1>
          </div>
          <p className="text-muted-foreground">Advanced offensive security tools and techniques</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {payloadTypes.map((type) => (
            <Card 
              key={type.name} 
              className="p-6 hover:border-cyber-red/50 transition-colors cursor-pointer bg-card/50 backdrop-blur-sm"
              onClick={() => {
                toast({ title: `${type.name} Payload`, description: `Loading ${type.description}...` });
                setSelectedPayload(type.category);
              }}
            >
              <type.icon className="h-8 w-8 text-cyber-red mb-3" />
              <h3 className="font-semibold mb-2 font-mono">{type.name}</h3>
              <p className="text-sm text-muted-foreground">{type.description}</p>
            </Card>
          ))}
        </div>

        <Card className="p-6 bg-card/50 backdrop-blur-sm">
          <div className="flex items-center gap-2 mb-4">
            <Target className="h-5 w-5 text-cyber-purple" />
            <h2 className="text-xl font-semibold font-mono">{selectedPayload ? "Payload Generator" : "TTP Database"}</h2>
          </div>
          {!selectedPayload ? (
            <>
              <p className="text-sm text-muted-foreground mb-4">MITRE ATT&CK framework tactics</p>
              <div className="space-y-2 mb-4">
                {["Initial Access", "Execution", "Persistence", "Lateral Movement"].map((tactic, idx) => (
                  <div key={tactic} className="flex justify-between items-center">
                    <span className="text-sm font-mono">{tactic}</span>
                    <Badge>{12 + idx} techniques</Badge>
                  </div>
                ))}
              </div>
              <Button className="w-full bg-cyber-purple hover:bg-cyber-purple/80 text-background" onClick={() => toast({ title: "TTP Database", description: "Opening MITRE ATT&CK..." })}>
                <Zap className="mr-2 h-4 w-4" />Browse Full Database
              </Button>
            </>
          ) : (
            <div className="space-y-4">
              <Button variant="ghost" size="sm" onClick={() => { setSelectedPayload(null); setGeneratedPayload(null); }}>← Back</Button>
              
              {selectedPayload === "shells" && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-sm font-medium">Target IP/Host</label>
                      <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.1" className="font-mono" />
                    </div>
                    <div>
                      <label className="text-sm font-medium">Port</label>
                      <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="4444" className="font-mono" />
                    </div>
                  </div>
                  <Button onClick={() => generatePayload("reverse-shell")} disabled={generating} className="w-full">
                    {generating ? "Generating..." : "Generate Reverse Shell"}
                  </Button>
                </div>
              )}
              
              {selectedPayload === "webshells" && (
                <Button onClick={() => generatePayload("webshell")} disabled={generating} className="w-full">
                  {generating ? "Generating..." : "Generate Web Shell"}
                </Button>
              )}
              
              {selectedPayload === "privesc" && (
                <Button onClick={() => generatePayload("privesc")} disabled={generating} className="w-full">
                  {generating ? "Generating..." : "Generate PrivEsc Payload"}
                </Button>
              )}
              
              {selectedPayload === "creds" && (
                <Button onClick={() => generatePayload("creds")} disabled={generating} className="w-full">
                  {generating ? "Generating..." : "Generate Credential Dump"}
                </Button>
              )}
              
              {selectedPayload === "lateral" && (
                <Button onClick={() => generatePayload("lateral")} disabled={generating} className="w-full">
                  {generating ? "Generating..." : "Generate Lateral Movement"}
                </Button>
              )}
              
              {selectedPayload === "obfuscation" && (
                <Button onClick={() => generatePayload("obfuscation")} disabled={generating} className="w-full">
                  {generating ? "Generating..." : "Generate Obfuscated Payload"}
                </Button>
              )}

              {generatedPayload && (
                <Card className="p-4 bg-background/50">
                  <div className="flex items-center justify-between mb-3">
                    <Badge variant="outline">{generatedPayload.type}</Badge>
                    <Button size="sm" variant="ghost">
                      <Download className="h-4 w-4 mr-2" />
                      Download
                    </Button>
                  </div>
                  {generatedPayload.instructions && (
                    <div className="mb-3 text-xs text-muted-foreground">
                      {generatedPayload.instructions}
                    </div>
                  )}
                  <Textarea 
                    value={generatedPayload.payload || ""} 
                    readOnly 
                    className="font-mono text-xs bg-black/50 min-h-[300px]"
                  />
                  {generatedPayload.usage && (
                    <div className="mt-3 p-3 bg-muted/50 rounded text-xs">
                      <div className="font-semibold mb-1">Usage:</div>
                      <pre className="text-muted-foreground whitespace-pre-wrap">{generatedPayload.usage}</pre>
                    </div>
                  )}
                </Card>
              )}
            </div>
          )}
        </Card>
      </main>
    </div>
  );
};

export default RedTeamModule;
