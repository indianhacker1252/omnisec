import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FileSearch, HardDrive, Database, Upload } from "lucide-react";

const ForensicsModule = () => {
  const artifacts = [
    {
      type: "Registry",
      location: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      timestamp: "2025-01-26 14:23:45",
      significance: "Persistence Mechanism",
    },
    {
      type: "File System",
      location: "C:\\Users\\Admin\\AppData\\Roaming\\suspicious.exe",
      timestamp: "2025-01-26 13:15:32",
      significance: "Malicious Executable",
    },
    {
      type: "Network",
      location: "TCP Connection to 192.168.1.100:4444",
      timestamp: "2025-01-26 14:20:11",
      significance: "C2 Communication",
    },
    {
      type: "Memory",
      location: "Process: svchost.exe (PID: 1337) - Injected Code",
      timestamp: "2025-01-26 14:25:00",
      significance: "Code Injection",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <FileSearch className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">Forensics & Incident Response</h1>
          </div>
          <p className="text-muted-foreground">
            Memory analysis, disk imaging, and digital forensics toolkit
          </p>
        </div>

        <Tabs defaultValue="artifacts" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="artifacts">
              <FileSearch className="h-4 w-4 mr-2" />
              Artifacts
            </TabsTrigger>
            <TabsTrigger value="memory">
              <Database className="h-4 w-4 mr-2" />
              Memory
            </TabsTrigger>
            <TabsTrigger value="disk">
              <HardDrive className="h-4 w-4 mr-2" />
              Disk
            </TabsTrigger>
            <TabsTrigger value="timeline">
              <FileSearch className="h-4 w-4 mr-2" />
              Timeline
            </TabsTrigger>
          </TabsList>

          <TabsContent value="artifacts" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Discovered Artifacts</h3>
                <Badge variant="outline">{artifacts.length} items</Badge>
              </div>

              <div className="space-y-3">
                {artifacts.map((artifact, idx) => (
                  <Card key={idx} className="p-4 border-cyber-purple/30">
                    <div className="flex items-start justify-between mb-2">
                      <Badge variant="secondary">{artifact.type}</Badge>
                      <span className="text-xs text-muted-foreground font-mono">
                        {artifact.timestamp}
                      </span>
                    </div>
                    <p className="text-sm font-mono mb-1">{artifact.location}</p>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          artifact.significance.includes("Malicious") ||
                          artifact.significance.includes("C2")
                            ? "destructive"
                            : "default"
                        }
                      >
                        {artifact.significance}
                      </Badge>
                    </div>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="memory">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Memory Dump Analysis</h3>
                <Button>
                  <Upload className="mr-2 h-4 w-4" />
                  Upload Dump
                </Button>
              </div>

              <div className="space-y-4">
                <Card className="p-4 bg-muted/50">
                  <h4 className="font-semibold mb-2">Volatility Framework</h4>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Processes</div>
                      <div className="font-mono font-semibold">142</div>
                    </div>
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Network Connections</div>
                      <div className="font-mono font-semibold">23</div>
                    </div>
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Suspicious DLLs</div>
                      <div className="font-mono font-semibold text-red-500">7</div>
                    </div>
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Handles</div>
                      <div className="font-mono font-semibold">3,421</div>
                    </div>
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Registry Keys</div>
                      <div className="font-mono font-semibold">1,892</div>
                    </div>
                    <div className="p-2 border rounded">
                      <div className="text-muted-foreground text-xs">Code Injections</div>
                      <div className="font-mono font-semibold text-red-500">3</div>
                    </div>
                  </div>
                </Card>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="disk">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Disk Imaging & Analysis</h3>
              <div className="space-y-4">
                <Card className="p-4 bg-muted/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <HardDrive className="h-8 w-8 text-cyber-purple" />
                      <div>
                        <div className="font-semibold">System Drive C:</div>
                        <div className="text-sm text-muted-foreground">NTFS - 512 GB</div>
                      </div>
                    </div>
                    <Button variant="outline">Create Image</Button>
                  </div>
                </Card>

                <div className="grid grid-cols-2 gap-4">
                  <Card className="p-4">
                    <div className="text-muted-foreground text-sm mb-1">Deleted Files Recovered</div>
                    <div className="text-2xl font-bold font-mono">47</div>
                  </Card>
                  <Card className="p-4">
                    <div className="text-muted-foreground text-sm mb-1">Hidden Partitions</div>
                    <div className="text-2xl font-bold font-mono text-yellow-500">2</div>
                  </Card>
                </div>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="timeline">
            <Card className="p-6 text-center border-dashed">
              <FileSearch className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                Interactive forensic timeline builder coming soon
              </p>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ForensicsModule;
