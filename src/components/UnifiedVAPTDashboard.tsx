/**
 * OmniSec™ Unified VAPT Dashboard
 * XBOW-like autonomous penetration testing with AI learning
 */

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import {
  Brain,
  Zap,
  Target,
  Shield,
  Globe,
  Search,
  Play,
  Pause,
  Square,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Activity,
  Eye,
  Download,
  Copy,
  ThumbsUp,
  ThumbsDown,
  Crosshair,
  Radar,
  Bug,
  Code,
  FileText,
  Network,
  Server,
  Cloud,
  Key,
  Lock,
  Terminal,
  Layers,
  GitBranch
} from "lucide-react";

interface Finding {
  id: string;
  severity: string;
  title: string;
  description: string;
  endpoint: string;
  method?: string;
  payload?: string;
  evidence?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  mitre?: string[];
  confidence: number;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
}

interface ScanResult {
  success: boolean;
  target: string;
  scanTime: number;
  discovery: {
    endpoints: number;
    subdomains: number;
    forms: number;
    apis: number;
  };
  fingerprint: any;
  findings: Finding[];
  attackPaths: any[];
  chainedExploits: any[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recommendations: string[];
}

export const UnifiedVAPTDashboard = () => {
  const { toast } = useToast();
  
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [liveFindings, setLiveFindings] = useState(0);
  const [liveEndpoints, setLiveEndpoints] = useState(0);
  const [currentEndpoint, setCurrentEndpoint] = useState('');
  
  // AI Settings
  const [enableLearning, setEnableLearning] = useState(true);
  const [retryWithAI, setRetryWithAI] = useState(true);
  const [generatePOC, setGeneratePOC] = useState(true);
  const [maxDepth, setMaxDepth] = useState(3);

  // Learning stats
  const [learningStats, setLearningStats] = useState({
    totalScans: 0,
    totalFindings: 0,
    learningPoints: 0,
    accuracy: 0
  });

  // Realtime subscription for scan progress
  const [scanId, setScanId] = useState<string | null>(null);

  useEffect(() => {
    loadLearningStats();
  }, []);

  useEffect(() => {
    if (!isScanning) return;

    const channel = supabase
      .channel('scan-progress-live')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'scan_progress',
        },
        (payload: any) => {
          const data = payload.new;
          setProgress(data.progress || 0);
          setCurrentPhase(data.message || data.phase || '');
          setLiveFindings(data.findings_so_far || 0);
          setLiveEndpoints(data.endpoints_discovered || 0);
          if (data.current_endpoint) setCurrentEndpoint(data.current_endpoint);

          if (data.phase === 'complete') {
            toast({
              title: "Phase Complete",
              description: data.message,
            });
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [isScanning]);

  const loadLearningStats = async () => {
    try {
      const { data: scans } = await supabase
        .from('scan_history')
        .select('id, findings_count, status')
        .order('created_at', { ascending: false })
        .limit(100);

      const { data: actions } = await supabase
        .from('vapt_test_actions')
        .select('outcome_label')
        .limit(500);

      const totalScans = scans?.length || 0;
      const totalFindings = scans?.reduce((sum, s) => sum + (s.findings_count || 0), 0) || 0;
      const successfulActions = actions?.filter(a => a.outcome_label === 'success').length || 0;
      const totalActions = actions?.length || 1;

      setLearningStats({
        totalScans,
        totalFindings,
        learningPoints: (actions?.length || 0),
        accuracy: Math.round((successfulActions / totalActions) * 100)
      });
    } catch (e) {
      console.error('Failed to load learning stats:', e);
    }
  };

  const runAutonomousVAPT = async () => {
    if (!target.trim()) {
      toast({ title: "Target Required", description: "Enter a target domain or IP", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setProgress(0);
    setLiveFindings(0);
    setLiveEndpoints(0);
    setCurrentEndpoint('');
    setScanResult(null);
    setSelectedFinding(null);
    setCurrentPhase('Initializing autonomous scanner...');

    try {
      const response = await supabase.functions.invoke('autonomous-vapt', {
        body: {
          target,
          action: 'full_scan',
          modules: ['all'],
          maxDepth,
          enableLearning,
          retryWithAI,
          generatePOC
        }
      });

      if (response.error) {
        // Edge function may have timed out but scan continues server-side
        // Poll database for results
        console.log('Edge function response error, polling for results...', response.error.message);
        await pollForResults(target);
        return;
      }

      const result = response.data as ScanResult;
      setScanResult(result);
      setProgress(100);
      setCurrentPhase('Scan complete!');

      await loadLearningStats();

      toast({
        title: "Autonomous VAPT Complete",
        description: `Found ${result.findings?.length || 0} vulnerabilities across ${result.discovery?.endpoints || 0} endpoints`
      });

    } catch (error: any) {
      console.error('Autonomous VAPT error:', error);
      // Connection may have timed out but scan continues on server
      // Poll DB for completed results
      await pollForResults(target);
    } finally {
      setIsScanning(false);
    }
  };

  const pollForResults = async (scanTarget: string) => {
    setCurrentPhase('Scan running server-side, checking for results...');
    // Extract clean domain for matching
    const cleanDomain = scanTarget.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    const pollStartTime = new Date().toISOString();
    
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise(r => setTimeout(r, 10000));
      
      try {
        // First check scan_history for a completed scan matching this target
        const { data: scans } = await supabase
          .from('scan_history')
          .select('id, target, status, findings_count')
          .or(`target.ilike.%${cleanDomain}%`)
          .eq('status', 'completed')
          .order('created_at', { ascending: false })
          .limit(1);

        if (scans && scans.length > 0) {
          const scan = scans[0];
          
          // Now get the security report linked to this scan
          const { data: reports } = await supabase
            .from('security_reports')
            .select('*')
            .eq('scan_id', scan.id)
            .limit(1);

          const report = reports?.[0];
          const findings = (report?.findings as any[] || []);
          const sevCounts = (report?.severity_counts as any) || {};
          
          setScanResult({
            success: true,
            target: scanTarget,
            scanTime: 0,
            discovery: { endpoints: 0, subdomains: 0, forms: 0, apis: 0 },
            fingerprint: {},
            findings,
            attackPaths: [],
            chainedExploits: [],
            summary: {
              critical: sevCounts.critical || 0,
              high: sevCounts.high || 0,
              medium: sevCounts.medium || 0,
              low: sevCounts.low || 0,
              info: sevCounts.info || 0,
            },
            recommendations: (report?.recommendations as string[]) || []
          });
          setProgress(100);
          setCurrentPhase('Scan complete! (retrieved from server)');
          await loadLearningStats();

          toast({
            title: "Autonomous VAPT Complete",
            description: `Found ${findings.length} vulnerabilities for ${cleanDomain}`
          });
          return;
        }
      } catch (e) {
        console.log('Poll attempt', attempt, 'failed:', e);
      }
      
      setProgress(Math.min(50 + attempt * 2, 95));
      setCurrentPhase(`Scan running server-side... checking (${attempt + 1}/30)`);
    }

    toast({
      title: "Scan Timeout",
      description: "Scan is still running on the server. Check back shortly.",
      variant: "destructive"
    });
  };

  const markFalsePositive = async (finding: Finding) => {
    try {
      await supabase.from('vapt_feedback').insert({
        rating: 'false_positive',
        comments: `Marked as false positive: ${finding.title}`,
      });
      
      if (scanResult) {
        const updatedFindings = scanResult.findings.map(f =>
          f.id === finding.id ? { ...f, falsePositive: true } : f
        );
        setScanResult({ ...scanResult, findings: updatedFindings });
      }
      
      toast({ title: "Feedback Recorded", description: "AI will learn from this for future scans" });
    } catch (e) {
      toast({ title: "Error", description: "Failed to record feedback", variant: "destructive" });
    }
  };

  const confirmVulnerability = async (finding: Finding) => {
    try {
      await supabase.from('vapt_feedback').insert({
        rating: 'confirmed',
        comments: `Confirmed vulnerability: ${finding.title}`,
      });
      
      toast({ title: "Vulnerability Confirmed", description: "Added to learning dataset" });
    } catch (e) {
      toast({ title: "Error", description: "Failed to record feedback", variant: "destructive" });
    }
  };

  const copyPOC = (poc: string) => {
    navigator.clipboard.writeText(poc);
    toast({ title: "Copied!", description: "POC copied to clipboard" });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-primary/20">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary/10 rounded-xl">
              <Crosshair className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Autonomous VAPT Engine</h1>
              <p className="text-muted-foreground">XBOW-like AI-powered penetration testing</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Badge variant="outline" className="gap-1 px-3 py-1">
              <Brain className="h-4 w-4" />
              {learningStats.learningPoints} Learning Points
            </Badge>
            <Badge variant="outline" className="gap-1 px-3 py-1">
              <TrendingUp className="h-4 w-4" />
              {learningStats.accuracy}% Accuracy
            </Badge>
          </div>
        </div>

        {/* Target Input */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="md:col-span-3">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter target (e.g., example.com, 192.168.1.1, https://target.com)"
              className="h-14 text-lg"
              disabled={isScanning}
            />
          </div>
          <Button
            onClick={runAutonomousVAPT}
            disabled={isScanning}
            className="h-14 text-lg gap-2"
            size="lg"
          >
            {isScanning ? (
              <>
                <RefreshCw className="h-5 w-5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Radar className="h-5 w-5" />
                Start Autonomous Scan
              </>
            )}
          </Button>
        </div>

        {/* AI Settings */}
        <div className="flex flex-wrap items-center gap-6 p-4 bg-background/50 rounded-lg">
          <div className="flex items-center gap-2">
            <Switch checked={enableLearning} onCheckedChange={setEnableLearning} />
            <span className="text-sm font-medium">AI Learning</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={retryWithAI} onCheckedChange={setRetryWithAI} />
            <span className="text-sm font-medium">Adaptive Payloads</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={generatePOC} onCheckedChange={setGeneratePOC} />
            <span className="text-sm font-medium">Generate POC</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Depth:</span>
            <select 
              value={maxDepth} 
              onChange={(e) => setMaxDepth(parseInt(e.target.value))}
              className="bg-background border rounded px-2 py-1 text-sm"
            >
              <option value="1">Shallow</option>
              <option value="3">Normal</option>
              <option value="5">Deep</option>
            </select>
          </div>
        </div>

        {/* Progress */}
        {isScanning && (
          <div className="mt-6 space-y-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4 animate-pulse" />
                {currentPhase}
              </span>
              <span className="text-sm text-muted-foreground">{progress}%</span>
            </div>
            <Progress value={progress} className="h-3" />
            <div className="flex items-center gap-6 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Globe className="h-3 w-3" /> {liveEndpoints} endpoints discovered
              </span>
              <span className="flex items-center gap-1">
                <Bug className="h-3 w-3" /> {liveFindings} findings so far
              </span>
              {currentEndpoint && (
                <span className="flex items-center gap-1 truncate max-w-xs">
                  <Target className="h-3 w-3" /> {currentEndpoint}
                </span>
              )}
            </div>
          </div>
        )}
      </Card>

      {/* Results */}
      {scanResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Summary Stats */}
          <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-6 gap-4">
            <Card className="p-4 text-center bg-red-500/10 border-red-500/30">
              <div className="text-3xl font-bold text-red-400">{scanResult.summary?.critical || 0}</div>
              <div className="text-sm text-muted-foreground">Critical</div>
            </Card>
            <Card className="p-4 text-center bg-orange-500/10 border-orange-500/30">
              <div className="text-3xl font-bold text-orange-400">{scanResult.summary?.high || 0}</div>
              <div className="text-sm text-muted-foreground">High</div>
            </Card>
            <Card className="p-4 text-center bg-yellow-500/10 border-yellow-500/30">
              <div className="text-3xl font-bold text-yellow-400">{scanResult.summary?.medium || 0}</div>
              <div className="text-sm text-muted-foreground">Medium</div>
            </Card>
            <Card className="p-4 text-center bg-blue-500/10 border-blue-500/30">
              <div className="text-3xl font-bold text-blue-400">{scanResult.summary?.low || 0}</div>
              <div className="text-sm text-muted-foreground">Low</div>
            </Card>
            <Card className="p-4 text-center bg-primary/10 border-primary/30">
              <div className="text-3xl font-bold text-primary">{scanResult.discovery?.endpoints || 0}</div>
              <div className="text-sm text-muted-foreground">Endpoints</div>
            </Card>
            <Card className="p-4 text-center bg-green-500/10 border-green-500/30">
              <div className="text-3xl font-bold text-green-400">{Math.round((scanResult.scanTime || 0) / 1000)}s</div>
              <div className="text-sm text-muted-foreground">Scan Time</div>
            </Card>
          </div>

          {/* Findings List */}
          <div className="lg:col-span-2">
            <Card className="p-4">
              <Tabs defaultValue="findings">
                <TabsList className="grid w-full grid-cols-3 mb-4">
                  <TabsTrigger value="findings" className="gap-2">
                    <Bug className="h-4 w-4" />
                    Findings ({scanResult.findings?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="attacks" className="gap-2">
                    <GitBranch className="h-4 w-4" />
                    Attack Paths
                  </TabsTrigger>
                  <TabsTrigger value="recommendations" className="gap-2">
                    <Shield className="h-4 w-4" />
                    Recommendations
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="findings">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-3">
                      {scanResult.findings?.filter(f => !f.falsePositive).map((finding) => (
                        <Card
                          key={finding.id}
                          className={`p-4 cursor-pointer transition-all hover:border-primary/50 ${
                            selectedFinding?.id === finding.id ? 'border-primary' : ''
                          }`}
                          onClick={() => setSelectedFinding(finding)}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity.toUpperCase()}
                              </Badge>
                              <span className="font-medium">{finding.title}</span>
                            </div>
                            <Badge variant="outline">{finding.confidence}% conf</Badge>
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2 mb-2">
                            {finding.description}
                          </p>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Globe className="h-3 w-3" />
                            <span className="truncate">{finding.endpoint}</span>
                            {finding.cwe && (
                              <Badge variant="outline" className="ml-auto text-xs">{finding.cwe}</Badge>
                            )}
                          </div>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="attacks">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-3">
                      {scanResult.attackPaths?.map((path, i) => (
                        <Card key={i} className="p-4">
                          <div className="flex items-center gap-2 mb-2">
                            <Layers className="h-4 w-4 text-primary" />
                            <span className="font-medium">{path.name}</span>
                          </div>
                          <p className="text-sm text-muted-foreground mb-2">{path.impact}</p>
                          <div className="space-y-1">
                            {path.steps?.map((step: string, j: number) => (
                              <div key={j} className="flex items-center gap-2 text-sm">
                                <span className="text-primary">{j + 1}.</span>
                                <span>{step}</span>
                              </div>
                            ))}
                          </div>
                        </Card>
                      ))}
                      {(!scanResult.attackPaths || scanResult.attackPaths.length === 0) && (
                        <div className="text-center text-muted-foreground py-8">
                          No attack paths identified
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="recommendations">
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-3">
                      {scanResult.recommendations?.map((rec, i) => (
                        <Card key={i} className="p-4 flex items-start gap-3">
                          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                          <span>{rec}</span>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>
              </Tabs>
            </Card>
          </div>

          {/* Finding Details */}
          <div className="lg:col-span-1">
            <Card className="p-4 h-full">
              {selectedFinding ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <Badge className={getSeverityColor(selectedFinding.severity)}>
                      {selectedFinding.severity.toUpperCase()}
                    </Badge>
                    <div className="flex gap-1">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => confirmVulnerability(selectedFinding)}
                        title="Confirm vulnerability"
                      >
                        <ThumbsUp className="h-4 w-4 text-green-500" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => markFalsePositive(selectedFinding)}
                        title="Mark as false positive"
                      >
                        <ThumbsDown className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  </div>
                  
                  <h3 className="font-bold text-lg">{selectedFinding.title}</h3>
                  
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <span className="break-all">{selectedFinding.endpoint}</span>
                    </div>
                    {selectedFinding.method && (
                      <div className="flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-muted-foreground" />
                        <Badge variant="outline">{selectedFinding.method}</Badge>
                      </div>
                    )}
                    {selectedFinding.cwe && (
                      <div className="flex items-center gap-2">
                        <Bug className="h-4 w-4 text-muted-foreground" />
                        <span>{selectedFinding.cwe}</span>
                      </div>
                    )}
                    {selectedFinding.cvss && (
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                        <span>CVSS: {selectedFinding.cvss}</span>
                      </div>
                    )}
                  </div>

                  <div>
                    <h4 className="font-medium mb-1">Description</h4>
                    <p className="text-sm text-muted-foreground">{selectedFinding.description}</p>
                  </div>

                  {selectedFinding.payload && (
                    <div>
                      <h4 className="font-medium mb-1">Payload</h4>
                      <code className="block text-xs bg-muted p-2 rounded font-mono break-all">
                        {selectedFinding.payload}
                      </code>
                    </div>
                  )}

                  {selectedFinding.evidence && (
                    <div>
                      <h4 className="font-medium mb-1">Evidence</h4>
                      <p className="text-sm text-muted-foreground">{selectedFinding.evidence}</p>
                    </div>
                  )}

                  <div>
                    <h4 className="font-medium mb-1">Remediation</h4>
                    <p className="text-sm text-muted-foreground">{selectedFinding.remediation}</p>
                  </div>

                  {selectedFinding.poc && (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <h4 className="font-medium">POC Command</h4>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => copyPOC(selectedFinding.poc!)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                      <pre className="text-xs bg-muted p-2 rounded font-mono overflow-x-auto whitespace-pre-wrap">
                        {selectedFinding.poc}
                      </pre>
                    </div>
                  )}

                  {selectedFinding.exploitCode && (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <h4 className="font-medium">Exploit Code</h4>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => copyPOC(selectedFinding.exploitCode!)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                      <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto max-h-48">
                        {selectedFinding.exploitCode}
                      </pre>
                    </div>
                  )}

                  {selectedFinding.mitre && selectedFinding.mitre.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-1">MITRE ATT&CK</h4>
                      <div className="flex flex-wrap gap-1">
                        {selectedFinding.mitre.map((id) => (
                          <Badge key={id} variant="outline">{id}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  <div className="text-center">
                    <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a finding to view details</p>
                  </div>
                </div>
              )}
            </Card>
          </div>
        </div>
      )}

      {/* Learning Stats */}
      <Card className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="h-6 w-6 text-primary" />
          <h3 className="text-lg font-bold">AI Learning Statistics</h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="p-4 bg-background/50">
            <div className="text-2xl font-bold text-primary">{learningStats.totalScans}</div>
            <div className="text-sm text-muted-foreground">Total Scans</div>
          </Card>
          <Card className="p-4 bg-background/50">
            <div className="text-2xl font-bold text-primary">{learningStats.totalFindings}</div>
            <div className="text-sm text-muted-foreground">Findings Discovered</div>
          </Card>
          <Card className="p-4 bg-background/50">
            <div className="text-2xl font-bold text-primary">{learningStats.learningPoints}</div>
            <div className="text-sm text-muted-foreground">Learning Data Points</div>
          </Card>
          <Card className="p-4 bg-background/50">
            <div className="text-2xl font-bold text-primary">{learningStats.accuracy}%</div>
            <div className="text-sm text-muted-foreground">Detection Accuracy</div>
          </Card>
        </div>
      </Card>
    </div>
  );
};

export default UnifiedVAPTDashboard;
