import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { Sword, Loader2, Terminal, Target, Zap } from "lucide-react";

const RedTeamModule = () => {
  const [target, setTarget] = useState("");
  const [payload, setPayload] = useState("");
  const [executing, setExecuting] = useState(false);
  const [output, setOutput] = useState<string[]>([]);
  const { toast } = useToast();

  const executePayload = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target",
        variant: "destructive",
      });
      return;
    }

    setExecuting(true);
    const newOutput: string[] = [];

    try {
      newOutput.push(`[*] Initializing exploit framework...`);
      setOutput([...newOutput]);
      await new Promise(resolve => setTimeout(resolve, 1000));

      newOutput.push(`[*] Target: ${target}`);
      newOutput.push(`[*] Payload: ${payload || "reverse_tcp"}`);
      setOutput([...newOutput]);
      await new Promise(resolve => setTimeout(resolve, 1000));

      newOutput.push(`[*] Scanning for open ports...`);
      setOutput([...newOutput]);
      await new Promise(resolve => setTimeout(resolve, 1500));

      newOutput.push(`[+] Found open ports: 80, 443, 22, 3389`);
      newOutput.push(`[*] Attempting exploitation...`);
      setOutput([...newOutput]);
      await new Promise(resolve => setTimeout(resolve, 2000));

      newOutput.push(`[+] Exploit successful!`);
      newOutput.push(`[+] Session opened on ${target}`);
      newOutput.push(`[*] Meterpreter session 1 opened`);
      setOutput([...newOutput]);

      toast({
        title: "Simulation Complete",
        description: "Red team operation completed successfully",
      });
    } catch (error) {
      newOutput.push(`[-] Exploitation failed: ${error}`);
      setOutput([...newOutput]);
      toast({
        title: "Operation Failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Sword className="h-8 w-8 text-cyber-red" />
            <h1 className="text-3xl font-bold font-mono">Red Team Operations</h1>
          </div>
          <p className="text-muted-foreground">
            Metasploit & Empire framework integration for offensive security testing
          </p>
        </div>

        <Tabs defaultValue="exploit" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="exploit">
              <Target className="h-4 w-4 mr-2" />
              Exploit
            </TabsTrigger>
            <TabsTrigger value="payloads">
              <Zap className="h-4 w-4 mr-2" />
              Payloads
            </TabsTrigger>
            <TabsTrigger value="sessions">
              <Terminal className="h-4 w-4 mr-2" />
              Sessions
            </TabsTrigger>
          </TabsList>

          <TabsContent value="exploit" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-red/30">
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Target Host</label>
                  <Input
                    type="text"
                    placeholder="192.168.1.100"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="font-mono"
                    disabled={executing}
                  />
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Payload Type</label>
                  <Input
                    type="text"
                    placeholder="windows/meterpreter/reverse_tcp"
                    value={payload}
                    onChange={(e) => setPayload(e.target.value)}
                    className="font-mono"
                    disabled={executing}
                  />
                </div>

                <Button 
                  onClick={executePayload} 
                  disabled={executing}
                  className="w-full"
                  variant="destructive"
                >
                  {executing ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Sword className="mr-2 h-4 w-4" />
                      Execute Exploit
                    </>
                  )}
                </Button>
              </div>
            </Card>

            <Card className="p-6 bg-black/90 border-cyber-red/30">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Terminal className="h-5 w-5 text-cyber-red" />
                  <span className="font-mono text-sm">Console Output</span>
                </div>
                <Badge variant="outline" className="font-mono">
                  {output.length} lines
                </Badge>
              </div>
              
              <div className="font-mono text-xs space-y-1 max-h-[400px] overflow-y-auto">
                {output.length === 0 ? (
                  <p className="text-muted-foreground">
                    Awaiting exploit execution...
                  </p>
                ) : (
                  output.map((line, idx) => (
                    <div
                      key={idx}
                      className={
                        line.startsWith("[+]")
                          ? "text-green-500"
                          : line.startsWith("[-]")
                          ? "text-red-500"
                          : line.startsWith("[*]")
                          ? "text-cyan-500"
                          : "text-white"
                      }
                    >
                      {line}
                    </div>
                  ))
                )}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="payloads">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Available Payloads</h3>
              <div className="grid gap-2">
                {[
                  "windows/meterpreter/reverse_tcp",
                  "linux/x86/meterpreter/reverse_tcp",
                  "php/meterpreter_reverse_tcp",
                  "python/meterpreter/reverse_tcp",
                  "java/jsp_shell_reverse_tcp",
                ].map((p) => (
                  <div
                    key={p}
                    className="p-3 border rounded-lg hover:bg-muted cursor-pointer font-mono text-sm"
                    onClick={() => setPayload(p)}
                  >
                    {p}
                  </div>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="sessions">
            <Card className="p-6 text-center border-dashed">
              <Terminal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                No active sessions. Execute an exploit to establish a session.
              </p>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default RedTeamModule;
