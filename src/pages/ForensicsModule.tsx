/**
 * OmniSec™ Forensics & Incident Response Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { useState, useRef } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FileSearch, HardDrive, Database, Upload, ArrowLeft, Loader2, AlertTriangle, FileText, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface AnalysisResult {
  artifacts?: any[];
  iocs?: any[];
  timeline?: any[];
  suspiciousFindings?: any[];
  recommendations?: string[];
  rawAnalysis?: string;
}

const ForensicsModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("upload");
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setAnalysisResult(null);
    }
  };

  const analyzeFile = async () => {
    if (!selectedFile) {
      toast({
        title: "No File Selected",
        description: "Please select a file to analyze",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      // Read file content
      const reader = new FileReader();
      reader.onload = async (e) => {
        const fileContent = e.target?.result as string;
        
        const { data, error } = await supabase.functions.invoke("forensics-analyze", {
          body: {
            action: "analyze",
            fileData: fileContent.substring(0, 100000), // Limit for API
            fileName: selectedFile.name,
            fileType: selectedFile.type || getFileType(selectedFile.name)
          }
        });

        if (error) throw error;

        if (data?.success) {
          setAnalysisResult(data);
          setActiveTab("results");
          toast({
            title: "Analysis Complete",
            description: `Successfully analyzed ${selectedFile.name}`
          });
        } else {
          throw new Error(data?.message || "Analysis failed");
        }
        setLoading(false);
      };

      reader.onerror = () => {
        throw new Error("Failed to read file");
      };

      // Read as text for logs, as base64 for binary
      if (isTextFile(selectedFile.name)) {
        reader.readAsText(selectedFile);
      } else {
        reader.readAsDataURL(selectedFile);
      }
    } catch (error: any) {
      console.error("Analysis error:", error);
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive"
      });
      setLoading(false);
    }
  };

  const getFileType = (fileName: string): string => {
    const ext = fileName.split('.').pop()?.toLowerCase() || '';
    const typeMap: Record<string, string> = {
      'evtx': 'Windows Event Log',
      'log': 'Log File',
      'pcap': 'Network Capture',
      'pcapng': 'Network Capture',
      'raw': 'Memory Dump',
      'dmp': 'Memory Dump',
      'mem': 'Memory Dump',
      'dd': 'Disk Image',
      'e01': 'Disk Image',
      'json': 'JSON Log',
      'csv': 'CSV Data',
      'xml': 'XML Data',
      'txt': 'Text File'
    };
    return typeMap[ext] || 'Unknown';
  };

  const isTextFile = (fileName: string): boolean => {
    const textExts = ['log', 'txt', 'json', 'csv', 'xml', 'evtx', 'html', 'htm'];
    const ext = fileName.split('.').pop()?.toLowerCase() || '';
    return textExts.includes(ext);
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6">
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
            AI-powered analysis of memory dumps, disk images, network captures, and log files
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="upload">
              <Upload className="h-4 w-4 mr-2" />
              Upload Evidence
            </TabsTrigger>
            <TabsTrigger value="results" disabled={!analysisResult}>
              <FileSearch className="h-4 w-4 mr-2" />
              Results
            </TabsTrigger>
            <TabsTrigger value="timeline" disabled={!analysisResult}>
              <Clock className="h-4 w-4 mr-2" />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="guide">
              <FileText className="h-4 w-4 mr-2" />
              Collection Guide
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="space-y-6">
            {/* Upload Section */}
            <Card className="p-8 border-dashed border-2 border-cyber-purple/30 hover:border-cyber-purple/50 transition-colors">
              <div className="text-center">
                <Upload className="h-16 w-16 mx-auto mb-4 text-cyber-purple" />
                <h3 className="text-xl font-semibold mb-2">Upload Forensic Evidence</h3>
                <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                  Upload memory dumps, disk images, network captures, or log files for AI-powered analysis
                </p>

                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileSelect}
                  className="hidden"
                  accept=".log,.txt,.json,.csv,.evtx,.pcap,.pcapng,.raw,.dmp,.mem,.xml,.html"
                />

                <div className="flex flex-col items-center gap-4">
                  <Button 
                    onClick={() => fileInputRef.current?.click()}
                    variant="outline"
                    className="gap-2 border-cyber-purple/50"
                  >
                    <Upload className="h-4 w-4" />
                    Select File
                  </Button>

                  {selectedFile && (
                    <div className="p-4 bg-muted/50 rounded-lg">
                      <div className="flex items-center gap-3">
                        <FileText className="h-8 w-8 text-cyber-cyan" />
                        <div className="text-left">
                          <p className="font-medium">{selectedFile.name}</p>
                          <p className="text-sm text-muted-foreground">
                            {(selectedFile.size / 1024).toFixed(1)} KB • {getFileType(selectedFile.name)}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  <Button 
                    onClick={analyzeFile}
                    disabled={!selectedFile || loading}
                    className="bg-cyber-purple hover:bg-cyber-purple/80"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <FileSearch className="h-4 w-4 mr-2" />
                        Analyze File
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </Card>

            {/* Supported Formats */}
            <Card className="p-6 border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">Supported Formats</h3>
              <div className="grid md:grid-cols-3 gap-4">
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Database className="h-4 w-4" />
                    Memory Analysis
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    <Badge variant="secondary">.raw</Badge>
                    <Badge variant="secondary">.dmp</Badge>
                    <Badge variant="secondary">.mem</Badge>
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <HardDrive className="h-4 w-4" />
                    Disk/Network
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    <Badge variant="secondary">.pcap</Badge>
                    <Badge variant="secondary">.pcapng</Badge>
                    <Badge variant="secondary">.dd</Badge>
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    Logs & Data
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    <Badge variant="secondary">.evtx</Badge>
                    <Badge variant="secondary">.log</Badge>
                    <Badge variant="secondary">.json</Badge>
                    <Badge variant="secondary">.csv</Badge>
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="results" className="space-y-4">
            {analysisResult && (
              <>
                {/* IOCs */}
                {analysisResult.iocs && analysisResult.iocs.length > 0 && (
                  <Card className="p-6 border-red-500/30 bg-red-500/5">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-500">
                      <AlertTriangle className="h-5 w-5" />
                      Indicators of Compromise ({analysisResult.iocs.length})
                    </h3>
                    <div className="space-y-2">
                      {analysisResult.iocs.map((ioc: any, idx: number) => (
                        <div key={idx} className="p-3 bg-background/50 rounded flex items-center justify-between">
                          <div>
                            <Badge variant="destructive" className="mr-2">{ioc.type}</Badge>
                            <span className="font-mono text-sm">{ioc.value}</span>
                          </div>
                          {ioc.confidence && (
                            <Badge variant="outline">{ioc.confidence}% confidence</Badge>
                          )}
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* Artifacts */}
                {analysisResult.artifacts && analysisResult.artifacts.length > 0 && (
                  <Card className="p-6 border-cyber-purple/30">
                    <h3 className="text-lg font-semibold mb-4">Discovered Artifacts</h3>
                    <div className="space-y-3">
                      {analysisResult.artifacts.map((artifact: any, idx: number) => (
                        <Card key={idx} className="p-4 border-cyber-purple/20">
                          <div className="flex items-start justify-between mb-2">
                            <Badge variant="secondary">{artifact.type}</Badge>
                            <span className="text-xs text-muted-foreground font-mono">{artifact.timestamp}</span>
                          </div>
                          <p className="text-sm font-mono mb-1">{artifact.location || artifact.path}</p>
                          <p className="text-sm text-muted-foreground">{artifact.significance || artifact.description}</p>
                        </Card>
                      ))}
                    </div>
                  </Card>
                )}

                {/* Suspicious Findings */}
                {analysisResult.suspiciousFindings && analysisResult.suspiciousFindings.length > 0 && (
                  <Card className="p-6 border-yellow-500/30 bg-yellow-500/5">
                    <h3 className="text-lg font-semibold mb-4 text-yellow-500">Suspicious Findings</h3>
                    <div className="space-y-2">
                      {analysisResult.suspiciousFindings.map((finding: any, idx: number) => (
                        <div key={idx} className="p-3 bg-background/50 rounded">
                          <p className="font-medium">{finding.title || finding.description}</p>
                          {finding.details && (
                            <p className="text-sm text-muted-foreground mt-1">{finding.details}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* Recommendations */}
                {analysisResult.recommendations && analysisResult.recommendations.length > 0 && (
                  <Card className="p-6 border-cyber-cyan/30">
                    <h3 className="text-lg font-semibold mb-4">Recommendations</h3>
                    <ul className="list-disc list-inside space-y-2 text-sm">
                      {analysisResult.recommendations.map((rec: string, idx: number) => (
                        <li key={idx} className="text-muted-foreground">{rec}</li>
                      ))}
                    </ul>
                  </Card>
                )}

                {/* Raw Analysis (fallback) */}
                {analysisResult.rawAnalysis && (
                  <Card className="p-6 border-cyber-purple/30">
                    <h3 className="text-lg font-semibold mb-4">Analysis Output</h3>
                    <pre className="text-xs font-mono bg-muted/50 p-4 rounded overflow-x-auto whitespace-pre-wrap">
                      {analysisResult.rawAnalysis}
                    </pre>
                  </Card>
                )}
              </>
            )}
          </TabsContent>

          <TabsContent value="timeline">
            {analysisResult?.timeline && analysisResult.timeline.length > 0 ? (
              <Card className="p-6 border-cyber-purple/30">
                <h3 className="text-lg font-semibold mb-4">Event Timeline</h3>
                <div className="space-y-4">
                  {analysisResult.timeline.map((event: any, idx: number) => (
                    <div key={idx} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className="w-3 h-3 rounded-full bg-cyber-purple" />
                        {idx < analysisResult.timeline!.length - 1 && (
                          <div className="w-0.5 h-full bg-cyber-purple/30" />
                        )}
                      </div>
                      <div className="flex-1 pb-4">
                        <p className="text-xs text-muted-foreground font-mono">{event.timestamp}</p>
                        <p className="font-medium">{event.event || event.description}</p>
                        {event.source && (
                          <Badge variant="outline" className="mt-1">{event.source}</Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            ) : (
              <Card className="p-8 text-center border-dashed border-cyber-purple/30">
                <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">Timeline will be generated from analyzed evidence</p>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="guide" className="space-y-4">
            <Card className="p-6 border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">Evidence Collection Guide</h3>
              
              <div className="space-y-6">
                <div>
                  <h4 className="font-medium mb-3">Memory Acquisition</h4>
                  <div className="p-4 bg-muted/50 rounded-lg">
                    <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Windows - Use winpmem
winpmem_mini_x64.exe memdump.raw

# Linux - Use LiME
sudo insmod lime.ko "path=/tmp/memdump.lime format=lime"

# Windows - Use DumpIt
DumpIt.exe`}
                    </pre>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium mb-3">Disk Imaging</h4>
                  <div className="p-4 bg-muted/50 rounded-lg">
                    <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Linux - dd command
sudo dd if=/dev/sda of=/path/to/image.dd bs=4M status=progress

# FTK Imager (GUI) - Create forensic image with verification

# dcfldd for progress and verification
sudo dcfldd if=/dev/sda of=/path/to/image.dd hash=sha256`}
                    </pre>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium mb-3">Network Capture</h4>
                  <div className="p-4 bg-muted/50 rounded-lg">
                    <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# tcpdump
sudo tcpdump -i eth0 -w capture.pcap

# Wireshark (GUI) - Start capture on interface

# tshark for command line
tshark -i eth0 -w capture.pcapng`}
                    </pre>
                  </div>
                </div>

                <div>
                  <h4 className="font-medium mb-3">Windows Log Collection</h4>
                  <div className="p-4 bg-muted/50 rounded-lg">
                    <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Export Security logs
wevtutil epl Security security.evtx

# Export all logs
wevtutil epl System system.evtx
wevtutil epl Application application.evtx

# PowerShell export
Get-WinEvent -LogName Security | Export-Csv security.csv`}
                    </pre>
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ForensicsModule;
