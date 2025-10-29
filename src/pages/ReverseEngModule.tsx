import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Code, FileCode, Cpu, Upload } from "lucide-react";

const ReverseEngModule = () => {
  const disassembly = [
    { addr: "0x00401000", bytes: "55", instruction: "push rbp", comment: "Function prologue" },
    { addr: "0x00401001", bytes: "48 89 e5", instruction: "mov rbp, rsp", comment: "" },
    { addr: "0x00401004", bytes: "48 83 ec 20", instruction: "sub rsp, 0x20", comment: "Allocate stack space" },
    { addr: "0x00401008", bytes: "e8 f3 00 00 00", instruction: "call 0x401100", comment: "Call suspicious function" },
    { addr: "0x0040100d", bytes: "48 83 c4 20", instruction: "add rsp, 0x20", comment: "Cleanup stack" },
    { addr: "0x00401011", bytes: "5d", instruction: "pop rbp", comment: "" },
    { addr: "0x00401012", bytes: "c3", instruction: "ret", comment: "Function epilogue" },
  ];

  const strings = [
    { addr: "0x00405000", content: "cmd.exe /c whoami", type: "Command" },
    { addr: "0x00405020", content: "192.168.1.100:4444", type: "Network" },
    { addr: "0x00405040", content: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", type: "Registry" },
    { addr: "0x00405080", content: "malware_loader.dll", type: "File" },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Code className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Reverse Engineering</h1>
          </div>
          <p className="text-muted-foreground">
            Ghidra, radare2, and IDA Pro integration for binary analysis
          </p>
        </div>

        <Card className="p-6 mb-6 bg-card/50 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold mb-1">Sample Binary</h3>
              <p className="text-sm text-muted-foreground font-mono">
                suspicious_payload.exe (SHA256: a4f3b2...)
              </p>
            </div>
            <Button>
              <Upload className="mr-2 h-4 w-4" />
              Upload Binary
            </Button>
          </div>
        </Card>

        <Tabs defaultValue="disasm" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="disasm">
              <Code className="h-4 w-4 mr-2" />
              Disassembly
            </TabsTrigger>
            <TabsTrigger value="strings">
              <FileCode className="h-4 w-4 mr-2" />
              Strings
            </TabsTrigger>
            <TabsTrigger value="functions">
              <Cpu className="h-4 w-4 mr-2" />
              Functions
            </TabsTrigger>
            <TabsTrigger value="imports">
              <FileCode className="h-4 w-4 mr-2" />
              Imports
            </TabsTrigger>
          </TabsList>

          <TabsContent value="disasm">
            <Card className="p-6 bg-black/90 border-cyber-cyan/30">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold font-mono">Disassembly Listing</h3>
                <Badge variant="outline">x86-64</Badge>
              </div>
              
              <div className="space-y-1 font-mono text-xs">
                {disassembly.map((line, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-12 gap-2 hover:bg-muted/20 px-2 py-1 rounded"
                  >
                    <div className="col-span-2 text-cyan-500">{line.addr}</div>
                    <div className="col-span-2 text-muted-foreground">{line.bytes}</div>
                    <div className="col-span-4 text-white">{line.instruction}</div>
                    <div className="col-span-4 text-green-500 text-[10px]">
                      {line.comment && `; ${line.comment}`}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="strings">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Extracted Strings</h3>
                <Badge variant="outline">{strings.length} found</Badge>
              </div>

              <div className="space-y-2">
                {strings.map((str, idx) => (
                  <Card key={idx} className="p-3 bg-muted/50">
                    <div className="flex items-start justify-between mb-1">
                      <span className="text-xs text-muted-foreground font-mono">
                        {str.addr}
                      </span>
                      <Badge
                        variant={
                          str.type === "Command" || str.type === "Network"
                            ? "destructive"
                            : "secondary"
                        }
                      >
                        {str.type}
                      </Badge>
                    </div>
                    <p className="font-mono text-sm break-all">{str.content}</p>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="functions">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Function Analysis</h3>
              <div className="space-y-2">
                {[
                  { name: "main", addr: "0x401000", size: "145 bytes", calls: 7 },
                  { name: "establish_persistence", addr: "0x401100", size: "89 bytes", calls: 3 },
                  { name: "connect_c2", addr: "0x401200", size: "234 bytes", calls: 12 },
                  { name: "execute_payload", addr: "0x401300", size: "178 bytes", calls: 5 },
                ].map((fn, idx) => (
                  <Card key={idx} className="p-4 hover:bg-muted/50 cursor-pointer">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-mono font-semibold">{fn.name}</div>
                        <div className="text-xs text-muted-foreground">
                          {fn.addr} • {fn.size} • {fn.calls} calls
                        </div>
                      </div>
                      <Code className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="imports">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Import Table</h3>
              <div className="grid md:grid-cols-2 gap-4">
                {[
                  { dll: "kernel32.dll", funcs: ["CreateProcessA", "WriteFile", "VirtualAlloc"] },
                  { dll: "ws2_32.dll", funcs: ["socket", "connect", "send", "recv"] },
                  { dll: "advapi32.dll", funcs: ["RegCreateKeyExA", "RegSetValueExA"] },
                  { dll: "ntdll.dll", funcs: ["NtQuerySystemInformation", "RtlDecompressBuffer"] },
                ].map((imp, idx) => (
                  <Card key={idx} className="p-4">
                    <div className="font-semibold mb-2 font-mono text-sm">{imp.dll}</div>
                    <div className="space-y-1">
                      {imp.funcs.map((fn, i) => (
                        <div key={i} className="text-xs font-mono text-muted-foreground pl-2">
                          • {fn}
                        </div>
                      ))}
                    </div>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ReverseEngModule;
