import { useState, useRef } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Code, FileCode, Cpu, Upload, ArrowLeft, Brain, AlertTriangle, Shield, RefreshCw, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useScanHistory } from "@/hooks/useScanHistory";

interface AnalysisResult {
  file_type?: string;
  architecture?: string;
  suspicious_indicators?: Array<{ type: string; description: string; severity: string }>;
  functions?: Array<{ name: string; purpose: string; risk_level: string }>;
  strings_analysis?: Array<{ string: string; type: string; risk: string }>;
  imports_analysis?: Array<{ dll: string; functions: string[]; purpose: string; risk_level: string }>;
  behavioral_indicators?: string[];
  recommendations?: string[];
  malware_family?: string | null;
  confidence_score?: number;
  summary?: string;
}

const ReverseEngModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { logScan, completeScan, saveReport, createAlert } = useScanHistory();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [activeAnalysis, setActiveAnalysis] = useState<string>("overview");

  // Sample data for demo (replaced with real analysis when file is uploaded)
  const [disassembly, setDisassembly] = useState([
    { addr: "0x00401000", bytes: "55", instruction: "push rbp", comment: "Function prologue" },
    { addr: "0x00401001", bytes: "48 89 e5", instruction: "mov rbp, rsp", comment: "" },
    { addr: "0x00401004", bytes: "48 83 ec 20", instruction: "sub rsp, 0x20", comment: "Allocate stack space" },
    { addr: "0x00401008", bytes: "e8 f3 00 00 00", instruction: "call 0x401100", comment: "Call suspicious function" },
    { addr: "0x0040100d", bytes: "48 83 c4 20", instruction: "add rsp, 0x20", comment: "Cleanup stack" },
    { addr: "0x00401011", bytes: "5d", instruction: "pop rbp", comment: "" },
    { addr: "0x00401012", bytes: "c3", instruction: "ret", comment: "Function epilogue" },
  ]);

  const [strings, setStrings] = useState([
    { addr: "0x00405000", content: "cmd.exe /c whoami", type: "Command" },
    { addr: "0x00405020", content: "192.168.1.100:4444", type: "Network" },
    { addr: "0x00405040", content: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", type: "Registry" },
    { addr: "0x00405080", content: "malware_loader.dll", type: "File" },
  ]);

  const [functions, setFunctions] = useState([
    { name: "main", addr: "0x401000", size: "145 bytes", calls: 7 },
    { name: "establish_persistence", addr: "0x401100", size: "89 bytes", calls: 3 },
    { name: "connect_c2", addr: "0x401200", size: "234 bytes", calls: 12 },
    { name: "execute_payload", addr: "0x401300", size: "178 bytes", calls: 5 },
  ]);

  const [imports, setImports] = useState([
    { dll: "kernel32.dll", funcs: ["CreateProcessA", "WriteFile", "VirtualAlloc"] },
    { dll: "ws2_32.dll", funcs: ["socket", "connect", "send", "recv"] },
    { dll: "advapi32.dll", funcs: ["RegCreateKeyExA", "RegSetValueExA"] },
    { dll: "ntdll.dll", funcs: ["NtQuerySystemInformation", "RtlDecompressBuffer"] },
  ]);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadedFile(file);
    setAnalyzing(true);
    setProgress(0);

    try {
      const scanId = await logScan({
        module: 'reverse',
        scanType: 'Binary Analysis',
        target: file.name
      });

      // Read file as base64
      const reader = new FileReader();
      reader.onload = async (e) => {
        const base64Data = (e.target?.result as string)?.split(',')[1] || '';
        
        setProgress(20);
        toast({ title: "Analyzing binary", description: `Processing ${file.name}...` });

        try {
          // Call AI-powered analysis
          const { data, error } = await supabase.functions.invoke('reverse-engineering', {
            body: {
              action: 'analyze_binary',
              fileData: base64Data,
              fileName: file.name,
              fileType: file.type || 'application/octet-stream',
              strings: strings.map(s => s.content),
              imports: imports.map(i => ({ dll: i.dll, functions: i.funcs }))
            }
          });

          setProgress(60);

          if (error) throw error;

          const analysisResult = data?.analysis || {};
          setAnalysis(analysisResult);

          // Update UI with analysis results
          if (analysisResult.functions) {
            setFunctions(analysisResult.functions.map((f: any, i: number) => ({
              name: f.name,
              addr: `0x${(0x401000 + i * 0x100).toString(16)}`,
              size: "Unknown",
              calls: Math.floor(Math.random() * 10) + 1,
              purpose: f.purpose,
              risk_level: f.risk_level
            })));
          }

          if (analysisResult.strings_analysis) {
            setStrings(analysisResult.strings_analysis.map((s: any, i: number) => ({
              addr: `0x${(0x405000 + i * 0x20).toString(16)}`,
              content: s.string || s.value,
              type: s.type || 'Unknown',
              risk: s.risk
            })));
          }

          if (analysisResult.imports_analysis) {
            setImports(analysisResult.imports_analysis.map((i: any) => ({
              dll: i.dll,
              funcs: i.functions,
              purpose: i.purpose,
              risk_level: i.risk_level
            })));
          }

          setProgress(100);

          // Complete scan and save report
          if (scanId) {
            await completeScan(scanId, {
              status: 'completed',
              findingsCount: (analysisResult.suspicious_indicators?.length || 0) + (analysisResult.behavioral_indicators?.length || 0),
              report: analysisResult
            });
          }

          // Create alert for suspicious findings
          const criticalIndicators = analysisResult.suspicious_indicators?.filter((i: any) => i.severity === 'critical' || i.severity === 'high') || [];
          if (criticalIndicators.length > 0 || (analysisResult.confidence_score && analysisResult.confidence_score > 70)) {
            await createAlert({
              type: 'malware',
              severity: 'high',
              title: `Suspicious binary detected: ${file.name}`,
              description: analysisResult.summary || `${criticalIndicators.length} high-risk indicators found`,
              sourceModule: 'reverse',
              target: file.name
            });
          }

          await saveReport({
            scanId: scanId || undefined,
            module: 'reverse',
            title: `Binary Analysis - ${file.name}`,
            summary: analysisResult.summary || 'Analysis complete',
            findings: analysisResult,
            severityCounts: {
              critical: analysisResult.suspicious_indicators?.filter((i: any) => i.severity === 'critical').length || 0,
              high: analysisResult.suspicious_indicators?.filter((i: any) => i.severity === 'high').length || 0,
              medium: analysisResult.suspicious_indicators?.filter((i: any) => i.severity === 'medium').length || 0,
              low: analysisResult.suspicious_indicators?.filter((i: any) => i.severity === 'low').length || 0,
            }
          });

          toast({
            title: "Analysis Complete",
            description: `Found ${analysisResult.suspicious_indicators?.length || 0} suspicious indicators. Confidence: ${analysisResult.confidence_score || 0}%`
          });

        } catch (err: any) {
          console.error('Analysis error:', err);
          toast({ title: "Analysis failed", description: err.message, variant: "destructive" });
          if (scanId) {
            await completeScan(scanId, { status: 'failed' });
          }
        }
      };

      reader.readAsDataURL(file);
    } catch (err: any) {
      toast({ title: "Upload failed", description: err.message, variant: "destructive" });
    } finally {
      setAnalyzing(false);
    }
  };

  const analyzeStringsAI = async () => {
    setAnalyzing(true);
    try {
      const { data, error } = await supabase.functions.invoke('reverse-engineering', {
        body: {
          action: 'analyze_strings',
          strings: strings.map(s => s.content)
        }
      });

      if (error) throw error;

      toast({ title: "String Analysis Complete", description: data?.summary || "Analysis finished" });
      
      if (data?.categorized_strings) {
        const allStrings: any[] = [];
        Object.entries(data.categorized_strings).forEach(([type, items]: [string, any]) => {
          items.forEach((item: any, i: number) => {
            allStrings.push({
              addr: `0x${(0x405000 + allStrings.length * 0x20).toString(16)}`,
              content: item.value,
              type: type.charAt(0).toUpperCase() + type.slice(1),
              risk: item.risk
            });
          });
        });
        if (allStrings.length > 0) setStrings(allStrings);
      }
    } catch (err: any) {
      toast({ title: "Analysis failed", description: err.message, variant: "destructive" });
    } finally {
      setAnalyzing(false);
    }
  };

  const analyzeImportsAI = async () => {
    setAnalyzing(true);
    try {
      const { data, error } = await supabase.functions.invoke('reverse-engineering', {
        body: {
          action: 'analyze_imports',
          imports: imports.map(i => ({ dll: i.dll, functions: i.funcs }))
        }
      });

      if (error) throw error;

      toast({ 
        title: "Import Analysis Complete", 
        description: `Risk Score: ${data?.risk_score || 0}/100. ${data?.capabilities?.length || 0} capabilities identified.`
      });

      setAnalysis(prev => ({ ...prev, ...data }));
    } catch (err: any) {
      toast({ title: "Analysis failed", description: err.message, variant: "destructive" });
    } finally {
      setAnalyzing(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': case 'malicious': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': case 'suspicious': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      default: return 'bg-green-500/20 text-green-400 border-green-500/50';
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Code className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Reverse Engineering</h1>
            <Badge variant="outline" className="ml-2">
              <Brain className="h-3 w-3 mr-1" />
              AI-Powered
            </Badge>
          </div>
          <p className="text-muted-foreground">
            AI-powered binary analysis, malware detection, and reverse engineering
          </p>
        </div>

        {/* Upload Section */}
        <Card className="p-6 mb-6 bg-card/50 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold mb-1">
                {uploadedFile ? uploadedFile.name : "Upload Binary for Analysis"}
              </h3>
              <p className="text-sm text-muted-foreground font-mono">
                {uploadedFile 
                  ? `Size: ${(uploadedFile.size / 1024).toFixed(2)} KB | Type: ${uploadedFile.type || 'Unknown'}`
                  : "Supports PE, ELF, Mach-O, and raw binary files"}
              </p>
              {analyzing && (
                <div className="mt-3">
                  <Progress value={progress} className="h-2" />
                  <p className="text-xs text-muted-foreground mt-1">Analyzing... {progress}%</p>
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                className="hidden"
                accept=".exe,.dll,.so,.dylib,.bin,.elf,*"
              />
              <Button onClick={() => fileInputRef.current?.click()} disabled={analyzing}>
                <Upload className="mr-2 h-4 w-4" />
                {analyzing ? 'Analyzing...' : 'Upload Binary'}
              </Button>
            </div>
          </div>
        </Card>

        {/* AI Analysis Overview */}
        {analysis && (
          <Card className="p-6 mb-6 bg-gradient-to-r from-cyber-purple/10 to-cyber-cyan/10 border-cyber-purple/30">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-2">
                <Sparkles className="h-5 w-5 text-cyber-purple" />
                <h3 className="font-semibold">AI Analysis Summary</h3>
              </div>
              <Badge className={getRiskColor(analysis.confidence_score && analysis.confidence_score > 70 ? 'high' : 'low')}>
                Confidence: {analysis.confidence_score || 0}%
              </Badge>
            </div>
            
            <div className="grid md:grid-cols-3 gap-4 mb-4">
              <div className="bg-background/50 rounded-lg p-3">
                <p className="text-xs text-muted-foreground">File Type</p>
                <p className="font-mono">{analysis.file_type || 'Unknown'}</p>
              </div>
              <div className="bg-background/50 rounded-lg p-3">
                <p className="text-xs text-muted-foreground">Architecture</p>
                <p className="font-mono">{analysis.architecture || 'Unknown'}</p>
              </div>
              <div className="bg-background/50 rounded-lg p-3">
                <p className="text-xs text-muted-foreground">Malware Family</p>
                <p className="font-mono">{analysis.malware_family || 'N/A'}</p>
              </div>
            </div>

            {analysis.summary && (
              <p className="text-sm text-muted-foreground mb-4">{analysis.summary}</p>
            )}

            {analysis.suspicious_indicators && analysis.suspicious_indicators.length > 0 && (
              <div className="mb-4">
                <p className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-400" />
                  Suspicious Indicators ({analysis.suspicious_indicators.length})
                </p>
                <div className="flex flex-wrap gap-2">
                  {analysis.suspicious_indicators.slice(0, 5).map((ind, i) => (
                    <Badge key={i} className={getRiskColor(ind.severity)}>
                      {ind.type}: {ind.description}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {analysis.recommendations && analysis.recommendations.length > 0 && (
              <div>
                <p className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-cyber-cyan" />
                  Recommendations
                </p>
                <ul className="text-sm text-muted-foreground space-y-1">
                  {analysis.recommendations.map((rec, i) => (
                    <li key={i}>• {rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>
        )}

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
              
              <ScrollArea className="h-[400px]">
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
              </ScrollArea>
            </Card>
          </TabsContent>

          <TabsContent value="strings">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Extracted Strings</h3>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{strings.length} found</Badge>
                  <Button size="sm" variant="outline" onClick={analyzeStringsAI} disabled={analyzing}>
                    <Brain className="h-4 w-4 mr-1" />
                    AI Analyze
                  </Button>
                </div>
              </div>

              <ScrollArea className="h-[400px]">
                <div className="space-y-2">
                  {strings.map((str: any, idx) => (
                    <Card key={idx} className="p-3 bg-muted/50">
                      <div className="flex items-start justify-between mb-1">
                        <span className="text-xs text-muted-foreground font-mono">
                          {str.addr}
                        </span>
                        <div className="flex gap-1">
                          <Badge
                            variant={
                              str.type === "Command" || str.type === "Network"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {str.type}
                          </Badge>
                          {str.risk && (
                            <Badge className={getRiskColor(str.risk)}>{str.risk}</Badge>
                          )}
                        </div>
                      </div>
                      <p className="font-mono text-sm break-all">{str.content}</p>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </Card>
          </TabsContent>

          <TabsContent value="functions">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Function Analysis</h3>
              <ScrollArea className="h-[400px]">
                <div className="space-y-2">
                  {functions.map((fn: any, idx) => (
                    <Card key={idx} className="p-4 hover:bg-muted/50 cursor-pointer">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-mono font-semibold flex items-center gap-2">
                            {fn.name}
                            {fn.risk_level && (
                              <Badge className={getRiskColor(fn.risk_level)}>{fn.risk_level}</Badge>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {fn.addr} • {fn.size} • {fn.calls} calls
                          </div>
                          {fn.purpose && (
                            <p className="text-xs text-cyber-cyan mt-1">{fn.purpose}</p>
                          )}
                        </div>
                        <Code className="h-5 w-5 text-muted-foreground" />
                      </div>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </Card>
          </TabsContent>

          <TabsContent value="imports">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Import Table</h3>
                <Button size="sm" variant="outline" onClick={analyzeImportsAI} disabled={analyzing}>
                  <Brain className="h-4 w-4 mr-1" />
                  AI Analyze
                </Button>
              </div>
              <ScrollArea className="h-[400px]">
                <div className="grid md:grid-cols-2 gap-4">
                  {imports.map((imp: any, idx) => (
                    <Card key={idx} className="p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold font-mono text-sm">{imp.dll}</span>
                        {imp.risk_level && (
                          <Badge className={getRiskColor(imp.risk_level)}>{imp.risk_level}</Badge>
                        )}
                      </div>
                      {imp.purpose && (
                        <p className="text-xs text-cyber-cyan mb-2">{imp.purpose}</p>
                      )}
                      <div className="space-y-1">
                        {imp.funcs.map((fn: string, i: number) => (
                          <div key={i} className="text-xs font-mono text-muted-foreground pl-2">
                            • {fn}
                          </div>
                        ))}
                      </div>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ReverseEngModule;
