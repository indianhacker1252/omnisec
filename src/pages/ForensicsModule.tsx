/**
 * OmniSec™ Forensics & Incident Response Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { useState, useEffect } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FileSearch, HardDrive, Database, Upload, ArrowLeft, RefreshCw, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Artifact {
  type: string;
  location: string;
  timestamp: string;
  significance: string;
  md5?: string;
  details?: string;
}

interface MemoryAnalysis {
  processes: number;
  networkConnections: number;
  suspiciousDlls: number;
  handles: number;
  registryKeys: number;
  codeInjections: number;
  suspiciousProcesses: Array<{ name: string; pid: number; threat: string }>;
}

interface DiskAnalysis {
  deletedFiles: number;
  hiddenPartitions: number;
  recoveredFiles: Array<{ name: string; path: string; deleted_at: string; type: string }>;
}

const ForensicsModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("artifacts");
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [memoryAnalysis, setMemoryAnalysis] = useState<MemoryAnalysis | null>(null);
  const [diskAnalysis, setDiskAnalysis] = useState<DiskAnalysis | null>(null);

  const fetchAnalysis = async (action: string) => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("forensics-analyze", {
        body: { action }
      });

      if (error) throw error;

      if (action === "artifacts" && data.artifacts) {
        setArtifacts(data.artifacts);
      } else if (action === "memory" && data.memoryAnalysis) {
        setMemoryAnalysis(data.memoryAnalysis);
      } else if (action === "disk" && data.diskAnalysis) {
        setDiskAnalysis(data.diskAnalysis);
      }

      toast({
        title: "Analysis Complete",
        description: `${action.charAt(0).toUpperCase() + action.slice(1)} analysis completed`,
      });
    } catch (error) {
      console.error("Forensics error:", error);
      toast({
        title: "Analysis Failed",
        description: "Failed to perform forensic analysis",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalysis("artifacts");
  }, []);

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    if (tab === "memory" && !memoryAnalysis) {
      fetchAnalysis("memory");
    } else if (tab === "disk" && !diskAnalysis) {
      fetchAnalysis("disk");
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2 border-cyber-purple/30">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <FileSearch className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">Forensics & Incident Response</h1>
          </div>
          <p className="text-muted-foreground">
            AI-powered memory analysis, disk imaging, and digital forensics toolkit
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
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
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Discovered Artifacts</h3>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{artifacts.length} items</Badge>
                  <Button 
                    size="sm" 
                    variant="outline" 
                    onClick={() => fetchAnalysis("artifacts")}
                    disabled={loading}
                    className="border-cyber-purple/30"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              {loading && artifacts.length === 0 ? (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-cyber-purple" />
                  <p className="text-muted-foreground">Analyzing artifacts...</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {artifacts.map((artifact, idx) => (
                    <Card key={idx} className="p-4 border-cyber-purple/30">
                      <div className="flex items-start justify-between mb-2">
                        <Badge variant="secondary">{artifact.type}</Badge>
                        <span className="text-xs text-muted-foreground font-mono">
                          {artifact.timestamp}
                        </span>
                      </div>
                      <p className="text-sm font-mono mb-1 break-all">{artifact.location}</p>
                      {artifact.md5 && (
                        <p className="text-xs text-muted-foreground font-mono mb-1">MD5: {artifact.md5}</p>
                      )}
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            artifact.significance.includes("Malicious") ||
                            artifact.significance.includes("C2") ||
                            artifact.significance.includes("Injection")
                              ? "destructive"
                              : "default"
                          }
                        >
                          {artifact.significance}
                        </Badge>
                      </div>
                      {artifact.details && (
                        <p className="text-xs text-muted-foreground mt-2">{artifact.details}</p>
                      )}
                    </Card>
                  ))}
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="memory">
            <Card className="p-6 border-cyber-purple/30">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Memory Dump Analysis</h3>
                <div className="flex gap-2">
                  <Button 
                    size="sm" 
                    variant="outline"
                    onClick={() => fetchAnalysis("memory")}
                    disabled={loading}
                    className="border-cyber-purple/30"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                  </Button>
                  <Button className="border-cyber-purple/30">
                    <Upload className="mr-2 h-4 w-4" />
                    Upload Dump
                  </Button>
                </div>
              </div>

              {loading && !memoryAnalysis ? (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-cyber-purple" />
                  <p className="text-muted-foreground">Analyzing memory dump...</p>
                </div>
              ) : memoryAnalysis ? (
                <div className="space-y-4">
                  <Card className="p-4 bg-muted/50 border-cyber-purple/30">
                    <h4 className="font-semibold mb-2">Volatility Framework Analysis</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Processes</div>
                        <div className="font-mono font-semibold">{memoryAnalysis.processes}</div>
                      </div>
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Network Connections</div>
                        <div className="font-mono font-semibold">{memoryAnalysis.networkConnections}</div>
                      </div>
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Suspicious DLLs</div>
                        <div className="font-mono font-semibold text-red-500">{memoryAnalysis.suspiciousDlls}</div>
                      </div>
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Handles</div>
                        <div className="font-mono font-semibold">{memoryAnalysis.handles.toLocaleString()}</div>
                      </div>
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Registry Keys</div>
                        <div className="font-mono font-semibold">{memoryAnalysis.registryKeys.toLocaleString()}</div>
                      </div>
                      <div className="p-2 border rounded border-cyber-purple/30">
                        <div className="text-muted-foreground text-xs">Code Injections</div>
                        <div className="font-mono font-semibold text-red-500">{memoryAnalysis.codeInjections}</div>
                      </div>
                    </div>
                  </Card>

                  {memoryAnalysis.suspiciousProcesses?.length > 0 && (
                    <Card className="p-4 bg-red-500/10 border-red-500/30">
                      <h4 className="font-semibold mb-2 text-red-500">Suspicious Processes Detected</h4>
                      <div className="space-y-2">
                        {memoryAnalysis.suspiciousProcesses.map((proc, idx) => (
                          <div key={idx} className="flex items-center justify-between text-sm">
                            <span className="font-mono">{proc.name} (PID: {proc.pid})</span>
                            <Badge variant="destructive">{proc.threat}</Badge>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Database className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">Click refresh to analyze memory</p>
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="disk">
            <Card className="p-6 border-cyber-purple/30">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Disk Imaging & Analysis</h3>
                <Button 
                  size="sm" 
                  variant="outline"
                  onClick={() => fetchAnalysis("disk")}
                  disabled={loading}
                  className="border-cyber-purple/30"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                </Button>
              </div>
              
              {loading && !diskAnalysis ? (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-cyber-purple" />
                  <p className="text-muted-foreground">Analyzing disk...</p>
                </div>
              ) : diskAnalysis ? (
                <div className="space-y-4">
                  <Card className="p-4 bg-muted/50 border-cyber-purple/30">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <HardDrive className="h-8 w-8 text-cyber-purple" />
                        <div>
                          <div className="font-semibold">System Drive C:</div>
                          <div className="text-sm text-muted-foreground">NTFS - 512 GB</div>
                        </div>
                      </div>
                      <Button variant="outline" className="border-cyber-purple/30">Create Image</Button>
                    </div>
                  </Card>

                  <div className="grid grid-cols-2 gap-4">
                    <Card className="p-4 border-cyber-purple/30">
                      <div className="text-muted-foreground text-sm mb-1">Deleted Files Recovered</div>
                      <div className="text-2xl font-bold font-mono">{diskAnalysis.deletedFiles}</div>
                    </Card>
                    <Card className="p-4 border-cyber-purple/30">
                      <div className="text-muted-foreground text-sm mb-1">Hidden Partitions</div>
                      <div className="text-2xl font-bold font-mono text-yellow-500">{diskAnalysis.hiddenPartitions}</div>
                    </Card>
                  </div>

                  {diskAnalysis.recoveredFiles?.length > 0 && (
                    <Card className="p-4 border-cyber-purple/30">
                      <h4 className="font-semibold mb-3">Recovered Files</h4>
                      <div className="space-y-2">
                        {diskAnalysis.recoveredFiles.map((file, idx) => (
                          <div key={idx} className="flex items-center justify-between text-sm p-2 bg-muted/50 rounded">
                            <div>
                              <span className="font-mono">{file.name}</span>
                              <span className="text-muted-foreground ml-2 text-xs">{file.path}</span>
                            </div>
                            <Badge variant="secondary">{file.type}</Badge>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <HardDrive className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">Click refresh to analyze disk</p>
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="timeline">
            <Card className="p-6 text-center border-dashed border-cyber-purple/30">
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
