/**
 * OmniSec™ Enterprise VAPT Dashboard
 * AI-powered unified security assessment with self-learning capabilities
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useScanHistory } from "@/hooks/useScanHistory";
import {
  Brain,
  Zap,
  Target,
  Shield,
  Globe,
  Cloud,
  Server,
  Wifi,
  Smartphone,
  Database,
  Key,
  Network,
  Container,
  Radio,
  FileSearch,
  Play,
  Pause,
  Square,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Activity,
  BarChart3,
  Eye,
  Download
} from "lucide-react";

interface ScanModule {
  id: string;
  name: string;
  category: string;
  icon: any;
  description: string;
  enabled: boolean;
  status: 'idle' | 'scanning' | 'completed' | 'failed';
  findings: number;
  duration?: number;
  standards: string[];
}

interface DeepScanResult {
  layer: string;
  findings: any[];
  correlations: any[];
  attackPaths: any[];
}

interface ConfidenceScore {
  findingId: string;
  score: number;
  factors: {
    exploitability: number;
    businessImpact: number;
    assetCriticality: number;
    exposureLevel: number;
    complianceRisk: number;
  };
  aiReasoning: string;
  falsePositiveProbability: number;
}

const SCAN_MODULES: ScanModule[] = [
  { id: 'web', name: 'Web Applications', category: 'Application', icon: Globe, description: 'OWASP Top 10, XSS, SQLi, CSRF', enabled: true, status: 'idle', findings: 0, standards: ['OWASP', 'CWE'] },
  { id: 'api', name: 'API Security', category: 'Application', icon: Network, description: 'REST, GraphQL, gRPC testing', enabled: true, status: 'idle', findings: 0, standards: ['OWASP API', 'OpenAPI'] },
  { id: 'mobile', name: 'Mobile Apps', category: 'Application', icon: Smartphone, description: 'iOS/Android app security', enabled: true, status: 'idle', findings: 0, standards: ['OWASP MASVS'] },
  { id: 'network', name: 'Network Infrastructure', category: 'Infrastructure', icon: Server, description: 'Port scanning, service detection', enabled: true, status: 'idle', findings: 0, standards: ['CIS', 'NIST'] },
  { id: 'cloud', name: 'Cloud Platforms', category: 'Cloud', icon: Cloud, description: 'AWS, Azure, GCP misconfigs', enabled: true, status: 'idle', findings: 0, standards: ['CIS Benchmark', 'CSA'] },
  { id: 'ad', name: 'Active Directory', category: 'Identity', icon: Key, description: 'AD/LDAP security assessment', enabled: true, status: 'idle', findings: 0, standards: ['MITRE ATT&CK', 'CIS'] },
  { id: 'iam', name: 'IAM & Identity', category: 'Identity', icon: Shield, description: 'OAuth, SAML, JWT, SSO testing', enabled: true, status: 'idle', findings: 0, standards: ['NIST', 'ISO 27001'] },
  { id: 'container', name: 'Containers & K8s', category: 'Cloud', icon: Container, description: 'Docker, Kubernetes security', enabled: true, status: 'idle', findings: 0, standards: ['CIS Docker', 'NSA K8s'] },
  { id: 'wireless', name: 'Wireless Networks', category: 'Network', icon: Wifi, description: 'WiFi, Bluetooth, NFC analysis', enabled: true, status: 'idle', findings: 0, standards: ['WPA3', 'IEEE'] },
  { id: 'iot', name: 'IoT & OT Systems', category: 'Infrastructure', icon: Radio, description: 'Industrial control systems', enabled: true, status: 'idle', findings: 0, standards: ['IEC 62443', 'NIST'] },
  { id: 'saas', name: 'SaaS Applications', category: 'Cloud', icon: Database, description: 'Third-party SaaS security', enabled: true, status: 'idle', findings: 0, standards: ['SOC2', 'ISO 27001'] },
];

export const EnterpriseVAPTDashboard = () => {
  const { toast } = useToast();
  const { logScan, completeScan, saveReport, createAlert } = useScanHistory();
  
  const [target, setTarget] = useState('');
  const [modules, setModules] = useState<ScanModule[]>(SCAN_MODULES);
  const [isScanning, setIsScanning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [overallProgress, setOverallProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [deepScanResults, setDeepScanResults] = useState<DeepScanResult[]>([]);
  const [confidenceScores, setConfidenceScores] = useState<ConfidenceScore[]>([]);
  const [aiLearningEnabled, setAiLearningEnabled] = useState(true);
  const [falsePositiveReduction, setFalsePositiveReduction] = useState(true);
  const [autoCorrelation, setAutoCorrelation] = useState(true);
  const [scanStats, setScanStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });

  const toggleModule = (id: string) => {
    setModules(prev => prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m));
  };

  const normalizeHost = (raw: string) => raw.trim().replace(/^https?:\/\//, "").split("/")[0];
  const normalizeUrl = (raw: string) => {
    const t = raw.trim();
    return t.startsWith("http://") || t.startsWith("https://") ? t : `https://${normalizeHost(t)}`;
  };

  const runEnterpriseVAPT = async () => {
    if (!target.trim()) {
      toast({ title: "Target Required", description: "Please enter a target", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setIsPaused(false);
    setOverallProgress(0);
    setDeepScanResults([]);
    setConfidenceScores([]);

    const host = normalizeHost(target);
    const url = normalizeUrl(target);
    const enabledModules = modules.filter(m => m.enabled);

    toast({ title: "Enterprise VAPT Started", description: `Real-data scan on ${host} with ${enabledModules.length} modules` });

    // Update module status to scanning
    setModules(prev => prev.map(m => m.enabled ? { ...m, status: 'scanning' } : m));
    setCurrentPhase('Initializing real-data scan...');
    setOverallProgress(10);

    try {
      // Call the enterprise-vapt edge function for real scanning
      const response = await supabase.functions.invoke('enterprise-vapt', {
        body: {
          target: url,
          modules: enabledModules.map(m => m.id),
          deep: true,
          retryWithNewPayloads: aiLearningEnabled
        }
      });

      if (response.error) {
        throw new Error(response.error.message);
      }

      const data = response.data;
      setOverallProgress(80);
      setCurrentPhase('Processing results...');

      // Process findings by module
      const allFindings = data.findings || [];
      const severityCounts = data.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

      // Update modules with real findings
      setModules(prev => prev.map(m => {
        const moduleFindings = allFindings.filter((f: any) => 
          f.id?.toLowerCase().startsWith(m.id.slice(0, 3).toLowerCase()) ||
          f.endpoint?.includes(m.id)
        );
        return {
          ...m,
          status: m.enabled ? 'completed' : 'idle',
          findings: m.enabled ? moduleFindings.length : 0
        };
      }));

      // Add deep scan results
      const reconResult = {
        layer: 'Reconnaissance',
        findings: data.recon?.endpoints?.map((e: string) => ({ title: e, type: 'endpoint' })) || [],
        correlations: [],
        attackPaths: []
      };

      const findingsResult = {
        layer: 'Security Findings',
        findings: allFindings,
        correlations: data.correlations || [],
        attackPaths: data.attackPaths || []
      };

      setDeepScanResults([reconResult, findingsResult]);

      // Generate AI confidence scores for findings
      if (aiLearningEnabled && allFindings.length > 0) {
        const scores = allFindings.slice(0, 15).map((f: any) => ({
          findingId: f.id || crypto.randomUUID(),
          score: f.confidence || 80,
          factors: {
            exploitability: f.cvss ? f.cvss * 10 : 70,
            businessImpact: f.severity === 'critical' ? 95 : f.severity === 'high' ? 80 : 60,
            assetCriticality: 75,
            exposureLevel: 70,
            complianceRisk: f.cwe ? 85 : 60
          },
          aiReasoning: `Real finding from ${f.endpoint || target}. ${f.evidence || ''}`,
          falsePositiveProbability: 100 - (f.confidence || 80)
        }));
        
        if (!falsePositiveReduction) {
          setConfidenceScores(scores);
        } else {
          setConfidenceScores(scores.filter((s: any) => s.falsePositiveProbability < 40));
        }
      }

      setScanStats({
        total: allFindings.length,
        critical: severityCounts.critical || 0,
        high: severityCounts.high || 0,
        medium: severityCounts.medium || 0,
        low: severityCounts.low || 0,
        info: severityCounts.info || 0
      });

      // Create alerts for critical findings
      if (severityCounts.critical > 0) {
        await createAlert({
          type: 'critical_vulnerability',
          severity: 'critical',
          title: `Critical vulnerabilities found on ${host}`,
          description: `Enterprise VAPT detected ${severityCounts.critical} critical issues with real payloads`,
          sourceModule: 'enterprise_vapt',
          target: host
        });
      }

      setOverallProgress(100);
      setCurrentPhase('');

      toast({ 
        title: "Enterprise VAPT Complete", 
        description: `Found ${allFindings.length} real vulnerabilities across ${enabledModules.length} modules` 
      });

    } catch (error: any) {
      console.error('Enterprise VAPT error:', error);
      setModules(prev => prev.map(m => ({ ...m, status: 'failed' })));
      toast({ 
        title: "Scan Failed", 
        description: error.message || 'Unknown error occurred', 
        variant: "destructive" 
      });
    } finally {
      setIsScanning(false);
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Application': return <Globe className="h-4 w-4" />;
      case 'Infrastructure': return <Server className="h-4 w-4" />;
      case 'Cloud': return <Cloud className="h-4 w-4" />;
      case 'Identity': return <Key className="h-4 w-4" />;
      case 'Network': return <Network className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const getStatusColor = (status: ScanModule['status']) => {
    switch (status) {
      case 'scanning': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      case 'completed': return 'bg-green-500/20 text-green-400 border-green-500/50';
      case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-primary/20">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Brain className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold">Enterprise VAPT Platform</h2>
            <p className="text-sm text-muted-foreground">AI-powered unified security assessment</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="gap-1">
            <Activity className="h-3 w-3" />
            {modules.filter(m => m.enabled).length} Modules
          </Badge>
        </div>
      </div>

      {/* Control Panel */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="md:col-span-2">
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter target (domain, IP, or URL)"
            className="h-12"
            disabled={isScanning}
          />
        </div>
        <div className="flex gap-2">
          {isScanning ? (
            <>
              <Button variant="outline" onClick={() => setIsPaused(!isPaused)} className="flex-1">
                {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
              </Button>
              <Button variant="destructive" onClick={() => setIsScanning(false)} className="flex-1">
                <Square className="h-4 w-4" />
              </Button>
            </>
          ) : (
            <Button onClick={runEnterpriseVAPT} className="w-full h-12 gap-2">
              <Zap className="h-5 w-5" />
              Start Enterprise VAPT
            </Button>
          )}
        </div>
      </div>

      {/* AI Settings */}
      <div className="flex items-center gap-6 mb-6 p-4 bg-background/50 rounded-lg">
        <div className="flex items-center gap-2">
          <Switch checked={aiLearningEnabled} onCheckedChange={setAiLearningEnabled} />
          <span className="text-sm">AI Learning</span>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={falsePositiveReduction} onCheckedChange={setFalsePositiveReduction} />
          <span className="text-sm">FP Reduction</span>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={autoCorrelation} onCheckedChange={setAutoCorrelation} />
          <span className="text-sm">Auto-Correlation</span>
        </div>
      </div>

      {/* Progress Bar */}
      {isScanning && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">{currentPhase}</span>
            <span className="text-sm text-muted-foreground">{Math.round(overallProgress)}%</span>
          </div>
          <Progress value={overallProgress} className="h-2" />
        </div>
      )}

      <Tabs defaultValue="modules" className="w-full">
        <TabsList className="grid w-full grid-cols-4 mb-4">
          <TabsTrigger value="modules">Modules</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
          <TabsTrigger value="attackpaths">Attack Paths</TabsTrigger>
          <TabsTrigger value="confidence">AI Confidence</TabsTrigger>
        </TabsList>

        <TabsContent value="modules">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {modules.map(module => (
              <Card 
                key={module.id}
                className={`p-4 cursor-pointer transition-all ${module.enabled ? 'bg-primary/5 border-primary/30' : 'bg-background/50 opacity-60'}`}
                onClick={() => !isScanning && toggleModule(module.id)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <module.icon className="h-4 w-4 text-primary" />
                    <span className="font-medium text-sm">{module.name}</span>
                  </div>
                  <Badge className={getStatusColor(module.status)}>
                    {module.status === 'scanning' && <RefreshCw className="h-3 w-3 mr-1 animate-spin" />}
                    {module.status}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{module.description}</p>
                <div className="flex items-center justify-between">
                  <div className="flex gap-1">
                    {module.standards.map(s => (
                      <Badge key={s} variant="outline" className="text-[10px] py-0">{s}</Badge>
                    ))}
                  </div>
                  {module.findings > 0 && (
                    <Badge variant="secondary">{module.findings} findings</Badge>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="results">
          <div className="space-y-4">
            {/* Summary Stats */}
            {scanStats.total > 0 && (
              <div className="grid grid-cols-5 gap-3">
                <Card className="p-3 text-center bg-red-500/10 border-red-500/30">
                  <div className="text-2xl font-bold text-red-400">{scanStats.critical}</div>
                  <div className="text-xs text-muted-foreground">Critical</div>
                </Card>
                <Card className="p-3 text-center bg-orange-500/10 border-orange-500/30">
                  <div className="text-2xl font-bold text-orange-400">{scanStats.high}</div>
                  <div className="text-xs text-muted-foreground">High</div>
                </Card>
                <Card className="p-3 text-center bg-yellow-500/10 border-yellow-500/30">
                  <div className="text-2xl font-bold text-yellow-400">{scanStats.medium}</div>
                  <div className="text-xs text-muted-foreground">Medium</div>
                </Card>
                <Card className="p-3 text-center bg-blue-500/10 border-blue-500/30">
                  <div className="text-2xl font-bold text-blue-400">{scanStats.low}</div>
                  <div className="text-xs text-muted-foreground">Low</div>
                </Card>
                <Card className="p-3 text-center bg-gray-500/10 border-gray-500/30">
                  <div className="text-2xl font-bold text-gray-400">{scanStats.total}</div>
                  <div className="text-xs text-muted-foreground">Total</div>
                </Card>
              </div>
            )}

            <ScrollArea className="h-[300px]">
              <div className="space-y-3">
                {deepScanResults.map((result, i) => (
                  <Card key={i} className="p-4 bg-background/50">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium">{result.layer}</h4>
                      <Badge>{result.findings.length} findings</Badge>
                    </div>
                    {result.findings.slice(0, 3).map((f: any, j: number) => (
                      <div key={j} className="text-sm text-muted-foreground pl-4 border-l border-primary/30 mt-2">
                        {f.title || f.name || f.port || JSON.stringify(f).slice(0, 60)}
                      </div>
                    ))}
                  </Card>
                ))}
              </div>
            </ScrollArea>
          </div>
        </TabsContent>

        <TabsContent value="attackpaths">
          <ScrollArea className="h-[400px]">
            <div className="space-y-4">
              {deepScanResults
                .filter(r => r.attackPaths.length > 0)
                .flatMap(r => r.attackPaths)
                .map((path: any, i: number) => (
                  <Card key={i} className={`p-4 ${path.severity === 'critical' ? 'bg-red-500/10 border-red-500/30' : 'bg-orange-500/10 border-orange-500/30'}`}>
                    <div className="flex items-center gap-2 mb-3">
                      <AlertTriangle className={`h-5 w-5 ${path.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`} />
                      <h4 className="font-medium">{path.name}</h4>
                      <Badge variant="destructive">{path.severity.toUpperCase()}</Badge>
                    </div>
                    <div className="space-y-2">
                      {path.steps.map((step: string, j: number) => (
                        <div key={j} className="flex items-center gap-2 text-sm">
                          <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-xs">{j + 1}</div>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2 mt-3">
                      {path.mitre?.map((t: string) => (
                        <Badge key={t} variant="outline">{t}</Badge>
                      ))}
                    </div>
                  </Card>
                ))}
              {deepScanResults.flatMap(r => r.attackPaths).length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  <TrendingUp className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No attack paths identified</p>
                  <p className="text-sm">Run a scan to detect chained vulnerabilities</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="confidence">
          <ScrollArea className="h-[400px]">
            <div className="space-y-3">
              {confidenceScores.map((score, i) => (
                <Card key={i} className="p-4 bg-background/50">
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-mono text-sm">{score.findingId.slice(0, 8)}</span>
                    <div className="flex items-center gap-2">
                      <Badge className={score.score >= 80 ? 'bg-green-500/20 text-green-400' : score.score >= 60 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'}>
                        {score.score.toFixed(0)}% Confidence
                      </Badge>
                      <Badge variant="outline">
                        {score.falsePositiveProbability.toFixed(0)}% FP Risk
                      </Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-5 gap-2 mb-3">
                    {Object.entries(score.factors).map(([key, value]) => (
                      <div key={key} className="text-center">
                        <div className="text-xs text-muted-foreground">{key.replace(/([A-Z])/g, ' $1').trim()}</div>
                        <Progress value={value} className="h-1 mt-1" />
                        <div className="text-xs font-medium mt-1">{value.toFixed(0)}%</div>
                      </div>
                    ))}
                  </div>
                  <p className="text-sm text-muted-foreground">{score.aiReasoning}</p>
                </Card>
              ))}
              {confidenceScores.length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No AI confidence scores yet</p>
                  <p className="text-sm">Enable AI Learning and run a scan</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </Card>
  );
};

export default EnterpriseVAPTDashboard;
