/**
 * OmniSec™ Kali Linux Integration Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Remote Security Tool Execution
 */

import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from "react-router-dom";
import { Terminal, Server, PlayCircle, StopCircle, Activity, ArrowLeft, CheckCircle, XCircle } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";

interface KaliTool {
  name: string;
  category: string;
  command: string;
  description: string;
}

const KaliIntegration = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [sshHost, setSshHost] = useState("");
  const [sshPort, setSshPort] = useState("22");
  const [sshUser, setSshUser] = useState("root");
  const [sshPassword, setSshPassword] = useState("");
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [output, setOutput] = useState<string[]>([]);
  const [commandInput, setCommandInput] = useState("");
  const [executing, setExecuting] = useState(false);

  const kaliTools: KaliTool[] = [
    { name: "nmap", category: "Scanner", command: "nmap -sV -sC", description: "Network scanner" },
    { name: "metasploit", category: "Exploit", command: "msfconsole", description: "Exploitation framework" },
    { name: "sqlmap", category: "Web", command: "sqlmap -u", description: "SQL injection tool" },
    { name: "aircrack-ng", category: "Wireless", command: "aircrack-ng", description: "Wireless security" },
    { name: "john", category: "Password", command: "john --wordlist=", description: "Password cracker" },
    { name: "hydra", category: "Password", command: "hydra -l -P", description: "Network login cracker" },
    { name: "burpsuite", category: "Web", command: "burpsuite", description: "Web proxy" },
    { name: "wireshark", category: "Network", command: "wireshark", description: "Packet analyzer" },
    { name: "nikto", category: "Web", command: "nikto -h", description: "Web scanner" },
    { name: "gobuster", category: "Web", command: "gobuster dir -u", description: "Directory brute-forcer" },
  ];

  const connectToKali = async () => {
    if (!sshHost || !sshUser || !sshPassword) {
      toast({
        title: "Missing Credentials",
        description: "Please provide all SSH connection details",
        variant: "destructive",
      });
      return;
    }

    setConnecting(true);
    setOutput((prev) => [...prev, `> Connecting to ${sshUser}@${sshHost}:${sshPort}...`]);

    try {
      // Simulate SSH connection - in production, use WebSocket to backend
      await new Promise((resolve) => setTimeout(resolve, 2000));
      
      setConnected(true);
      setOutput((prev) => [
        ...prev,
        `✓ Connected to Kali Linux`,
        `✓ Kernel: 5.16.0-kali7-amd64`,
        `✓ Tools: ${kaliTools.length} available`,
        ``,
        `Ready to execute commands...`,
      ]);

      toast({
        title: "Connected",
        description: `Successfully connected to ${sshHost}`,
      });
    } catch (error) {
      toast({
        title: "Connection Failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
      setOutput((prev) => [...prev, `✗ Connection failed`]);
    } finally {
      setConnecting(false);
    }
  };

  const disconnectFromKali = () => {
    setConnected(false);
    setOutput((prev) => [...prev, ``, `> Disconnected from Kali Linux`, ``]);
    toast({
      title: "Disconnected",
      description: "SSH connection closed",
    });
  };

  const executeCommand = async () => {
    if (!commandInput.trim()) return;
    if (!connected) {
      toast({
        title: "Not Connected",
        description: "Please connect to Kali Linux first",
        variant: "destructive",
      });
      return;
    }

    setExecuting(true);
    const cmd = commandInput.trim();
    setOutput((prev) => [...prev, ``, `$ ${cmd}`]);
    setCommandInput("");

    try {
      // Simulate command execution
      await new Promise((resolve) => setTimeout(resolve, 1500));
      
      // Mock responses based on command
      let response = "";
      if (cmd.includes("nmap")) {
        response = `Starting Nmap scan...\nHost is up (0.023s latency)\nPORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\nNmap done: 1 IP address (1 host up) scanned in 2.34 seconds`;
      } else if (cmd.includes("whoami")) {
        response = sshUser;
      } else if (cmd.includes("uname")) {
        response = "Linux kali 5.16.0-kali7-amd64 #1 SMP PREEMPT Debian 5.16.18-1kali1 (2022-04-01) x86_64 GNU/Linux";
      } else if (cmd.includes("ls")) {
        response = "Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos";
      } else {
        response = `Command executed: ${cmd}\nOutput would appear here in production`;
      }

      setOutput((prev) => [...prev, response]);
    } catch (error) {
      setOutput((prev) => [...prev, `Error: ${error instanceof Error ? error.message : "Command failed"}`]);
    } finally {
      setExecuting(false);
    }
  };

  const quickLaunchTool = (tool: KaliTool) => {
    setCommandInput(tool.command);
    toast({
      title: "Command Ready",
      description: `${tool.name} command loaded. Add parameters and execute.`,
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />

      <main className="container mx-auto px-6 py-8">
        <Button
          variant="ghost"
          onClick={() => navigate("/")}
          className="mb-6 gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Terminal className="h-8 w-8 text-cyber-green" />
            <h1 className="text-3xl font-bold font-mono">Kali Linux Integration</h1>
          </div>
          <p className="text-muted-foreground">
            Remote SSH connection and tool execution on Kali Linux systems
          </p>
        </div>

        <Tabs defaultValue="connection" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="connection">Connection</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
            <TabsTrigger value="terminal">Terminal</TabsTrigger>
          </TabsList>

          <TabsContent value="connection">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Server className="h-5 w-5 text-cyber-green" />
                  SSH Connection
                </h3>
                {connected ? (
                  <Badge className="bg-cyber-green text-background">
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Connected
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Disconnected
                  </Badge>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="text-sm font-medium mb-2 block">Host</label>
                  <Input
                    type="text"
                    placeholder="192.168.1.100"
                    value={sshHost}
                    onChange={(e) => setSshHost(e.target.value)}
                    disabled={connected}
                    className="font-mono"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">Port</label>
                  <Input
                    type="text"
                    placeholder="22"
                    value={sshPort}
                    onChange={(e) => setSshPort(e.target.value)}
                    disabled={connected}
                    className="font-mono"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">Username</label>
                  <Input
                    type="text"
                    placeholder="root"
                    value={sshUser}
                    onChange={(e) => setSshUser(e.target.value)}
                    disabled={connected}
                    className="font-mono"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">Password</label>
                  <Input
                    type="password"
                    placeholder="••••••••"
                    value={sshPassword}
                    onChange={(e) => setSshPassword(e.target.value)}
                    disabled={connected}
                    className="font-mono"
                  />
                </div>
              </div>

              {!connected ? (
                <Button
                  onClick={connectToKali}
                  disabled={connecting}
                  className="w-full bg-cyber-green hover:bg-cyber-green/80 text-background"
                >
                  {connecting ? (
                    <>
                      <Activity className="h-4 w-4 mr-2 animate-spin" />
                      Connecting...
                    </>
                  ) : (
                    <>
                      <PlayCircle className="h-4 w-4 mr-2" />
                      Connect to Kali Linux
                    </>
                  )}
                </Button>
              ) : (
                <Button
                  onClick={disconnectFromKali}
                  variant="destructive"
                  className="w-full"
                >
                  <StopCircle className="h-4 w-4 mr-2" />
                  Disconnect
                </Button>
              )}

              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">
                  <strong>Note:</strong> This feature requires:
                </p>
                <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                  <li>Kali Linux VM or physical machine with SSH enabled</li>
                  <li>Network connectivity to the target system</li>
                  <li>Valid SSH credentials</li>
                  <li>Backend WebSocket service for command relay (setup via AI assistant)</li>
                </ul>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="tools">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4">Available Kali Tools</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {kaliTools.map((tool) => (
                  <Card key={tool.name} className="p-4 bg-background/50">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold font-mono">{tool.name}</h4>
                      <Badge variant="secondary" className="text-xs">
                        {tool.category}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">
                      {tool.description}
                    </p>
                    <code className="text-xs bg-muted p-2 rounded block mb-3 font-mono">
                      {tool.command}
                    </code>
                    <Button
                      size="sm"
                      onClick={() => quickLaunchTool(tool)}
                      disabled={!connected}
                      className="w-full"
                    >
                      <PlayCircle className="h-3 w-3 mr-1" />
                      Load Command
                    </Button>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="terminal">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Terminal className="h-5 w-5 text-cyber-green" />
                Interactive Terminal
              </h3>

              <Card className="bg-black/90 p-4 mb-4 border-cyber-green/30">
                <ScrollArea className="h-[400px]">
                  <div className="font-mono text-sm text-cyber-green space-y-1">
                    {output.map((line, idx) => (
                      <div key={idx} className="whitespace-pre-wrap">
                        {line}
                      </div>
                    ))}
                    {executing && (
                      <div className="flex items-center gap-2">
                        <Activity className="h-4 w-4 animate-spin" />
                        <span>Executing...</span>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </Card>

              <div className="flex gap-2">
                <Input
                  value={commandInput}
                  onChange={(e) => setCommandInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") executeCommand();
                  }}
                  placeholder={connected ? "Enter command..." : "Connect to Kali first"}
                  disabled={!connected || executing}
                  className="font-mono bg-black/50 text-cyber-green border-cyber-green/30"
                />
                <Button
                  onClick={executeCommand}
                  disabled={!connected || executing || !commandInput.trim()}
                  className="bg-cyber-green hover:bg-cyber-green/80 text-background"
                >
                  {executing ? (
                    <Activity className="h-4 w-4 animate-spin" />
                  ) : (
                    <PlayCircle className="h-4 w-4" />
                  )}
                </Button>
              </div>

              <div className="mt-4 text-xs text-muted-foreground">
                <p>
                  <strong>Tip:</strong> Press Enter to execute commands. Use the Tools tab
                  to quick-load common Kali tools.
                </p>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default KaliIntegration;
