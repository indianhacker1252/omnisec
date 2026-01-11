/**
 * OmniSec™ Automated Workflow Engine
 * Orchestrates multi-step security testing workflows with REAL scanning
 */

import { useState, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useScanHistory } from "@/hooks/useScanHistory";
import {
  Play,
  Pause,
  Square,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Settings,
  Zap,
  RefreshCw,
  ChevronRight,
  Download,
} from "lucide-react";

interface WorkflowStep {
  id: string;
  name: string;
  module: string;
  functionName: string;
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  duration?: number;
  findings?: number;
  error?: string;
  data?: any;
}

interface Workflow {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  status: 'idle' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  target?: string;
  totalFindings?: number;
}

const PRESET_WORKFLOWS = [
  {
    id: 'full-pentest',
    name: 'Full Penetration Test',
    description: 'Complete security assessment including recon, vuln scan, and all modules',
    steps: [
      { id: '1', name: 'Subdomain Enumeration', module: 'recon', functionName: 'subdomain-enum', status: 'pending' as const },
      { id: '2', name: 'Reconnaissance', module: 'recon', functionName: 'recon', status: 'pending' as const },
      { id: '3', name: 'Endpoint Discovery', module: 'recon', functionName: 'endpoint-discovery', status: 'pending' as const },
      { id: '4', name: 'Web Application Scan', module: 'webapp', functionName: 'webapp-scan', status: 'pending' as const },
      { id: '5', name: 'API Security Test', module: 'api-security', functionName: 'api-security', status: 'pending' as const },
      { id: '6', name: 'Cloud Security Audit', module: 'cloud-security', functionName: 'cloud-security', status: 'pending' as const },
      { id: '7', name: 'IAM Security Check', module: 'iam-security', functionName: 'iam-security', status: 'pending' as const },
      { id: '8', name: 'Vulnerability Intel', module: 'vuln', functionName: 'vulnintel', status: 'pending' as const },
      { id: '9', name: 'AI Attack Synthesis', module: 'autonomous', functionName: 'autonomous-attack', status: 'pending' as const },
    ]
  },
  {
    id: 'web-assessment',
    name: 'Web Application Assessment',
    description: 'Focused web application security testing',
    steps: [
      { id: '1', name: 'Reconnaissance', module: 'recon', functionName: 'recon', status: 'pending' as const },
      { id: '2', name: 'Web Application Scan', module: 'webapp', functionName: 'webapp-scan', status: 'pending' as const },
      { id: '3', name: 'Vulnerability Intel', module: 'vuln', functionName: 'vulnintel', status: 'pending' as const },
    ]
  },
  {
    id: 'cloud-audit',
    name: 'Cloud Security Audit',
    description: 'AWS/Azure/GCP misconfiguration detection',
    steps: [
      { id: '1', name: 'Reconnaissance', module: 'recon', functionName: 'recon', status: 'pending' as const },
      { id: '2', name: 'Cloud Security Scan', module: 'cloud-security', functionName: 'cloud-security', status: 'pending' as const },
      { id: '3', name: 'IAM Security Check', module: 'iam-security', functionName: 'iam-security', status: 'pending' as const },
    ]
  },
  {
    id: 'api-test',
    name: 'API Security Testing',
    description: 'OWASP API Top 10 security testing',
    steps: [
      { id: '1', name: 'Endpoint Discovery', module: 'recon', functionName: 'endpoint-discovery', status: 'pending' as const },
      { id: '2', name: 'API Security Scan', module: 'api-security', functionName: 'api-security', status: 'pending' as const },
      { id: '3', name: 'Vulnerability Intel', module: 'vuln', functionName: 'vulnintel', status: 'pending' as const },
    ]
  }
];

export const AutomatedWorkflow = () => {
  const { toast } = useToast();
  const { logScan, completeScan, saveReport, createAlert } = useScanHistory();
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>('full-pentest');
  const [target, setTarget] = useState('');
  const [workflow, setWorkflow] = useState<Workflow | null>(null);
  const [autoRetry, setAutoRetry] = useState(true);
  const [isPaused, setIsPaused] = useState(false);

  const normalizeHost = (raw: string) => raw.trim().replace(/^https?:\/\//, "").split("/")[0];
  const normalizeUrl = (raw: string) => {
    const t = raw.trim();
    if (t.startsWith("http://") || t.startsWith("https://")) return t;
    return `https://${normalizeHost(t)}`;
  };

  const initializeWorkflow = () => {
    const preset = PRESET_WORKFLOWS.find(w => w.id === selectedWorkflow);
    if (!preset) return;

    if (!target.trim()) {
      toast({ title: "Target Required", description: "Please enter a target URL or domain", variant: "destructive" });
      return;
    }

    setWorkflow({
      ...preset,
      status: 'idle',
      progress: 0,
      target,
      totalFindings: 0,
      steps: preset.steps.map(s => ({ ...s }))
    });

    toast({ title: "Workflow Initialized", description: `${preset.name} ready to execute on ${target}` });
  };

  const executeStep = async (step: WorkflowStep, host: string, url: string): Promise<{ success: boolean; findings: number; data: any }> => {
    const startTime = Date.now();
    
    try {
      let body: any = {};
      
      switch (step.functionName) {
        case 'recon':
          body = { target: host };
          break;
        case 'subdomain-enum':
          body = { domain: host };
          break;
        case 'endpoint-discovery':
          body = { target: url };
          break;
        case 'webapp-scan':
          body = { target: url };
          break;
        case 'api-security':
          body = { target: url, scanType: 'comprehensive' };
          break;
        case 'cloud-security':
          body = { provider: 'auto', target: host };
          break;
        case 'iam-security':
          body = { target: host, scanType: 'full' };
          break;
        case 'vulnintel':
          body = { query: host };
          break;
        case 'autonomous-attack':
          body = { target: host, objective: 'Full VAPT analysis' };
          break;
        default:
          body = { target: host };
      }

      const response = await supabase.functions.invoke(step.functionName, { body });
      
      if (response.error) {
        throw response.error;
      }

      const data = response.data || {};
      let findings = 0;

      // Extract findings count
      if (data.ports) findings = data.ports.length;
      else if (data.subdomains) findings = data.subdomains.length;
      else if (data.endpoints) findings = data.endpoints.length;
      else if (data.findings) findings = data.findings.length;
      else if (data.vulnerabilities) findings = data.vulnerabilities.length;
      else if (data.count) findings = data.count;
      else if (data.attack_chain) findings = data.attack_chain.length;
      else if (data.total) findings = data.total;

      return { success: true, findings, data };
    } catch (error: any) {
      throw error;
    }
  };

  const executeWorkflow = async () => {
    if (!workflow) return;

    const host = normalizeHost(workflow.target || '');
    const url = normalizeUrl(workflow.target || '');

    setWorkflow(prev => prev ? { ...prev, status: 'running' } : null);
    setIsPaused(false);

    let totalFindings = 0;
    const allResults: Record<string, any> = {};

    for (let i = 0; i < workflow.steps.length; i++) {
      if (isPaused) {
        setWorkflow(prev => prev ? { ...prev, status: 'paused' } : null);
        return;
      }

      const step = workflow.steps[i];
      const startTime = Date.now();
      
      // Update step to running
      setWorkflow(prev => {
        if (!prev) return null;
        const newSteps = [...prev.steps];
        newSteps[i] = { ...newSteps[i], status: 'running' };
        return { ...prev, steps: newSteps, progress: ((i) / prev.steps.length) * 100 };
      });

      // Log scan start
      const scanId = await logScan({ 
        module: step.module, 
        scanType: `Workflow - ${step.name}`, 
        target: host 
      });

      try {
        const result = await executeStep(step, host, url);
        const duration = Date.now() - startTime;
        totalFindings += result.findings;
        allResults[step.functionName] = result.data;

        // Update step to success
        setWorkflow(prev => {
          if (!prev) return null;
          const newSteps = [...prev.steps];
          newSteps[i] = {
            ...newSteps[i],
            status: 'success',
            duration,
            findings: result.findings,
            data: result.data
          };
          return {
            ...prev,
            steps: newSteps,
            progress: ((i + 1) / prev.steps.length) * 100,
            totalFindings
          };
        });

        // Complete scan in database
        if (scanId) {
          await completeScan(scanId, { 
            status: 'completed', 
            findingsCount: result.findings, 
            report: result.data 
          });
        }

      } catch (error: any) {
        const duration = Date.now() - startTime;

        // Update step to failed
        setWorkflow(prev => {
          if (!prev) return null;
          const newSteps = [...prev.steps];
          newSteps[i] = {
            ...newSteps[i],
            status: 'failed',
            duration,
            error: error?.message || 'Step failed'
          };
          return {
            ...prev,
            steps: newSteps,
            progress: ((i + 1) / prev.steps.length) * 100
          };
        });

        if (scanId) {
          await completeScan(scanId, { status: 'failed' });
        }

        // Auto-retry on failure if enabled
        if (autoRetry) {
          toast({ title: "Retrying Step", description: `Retrying ${step.name}...` });
          
          try {
            const retryResult = await executeStep(step, host, url);
            const retryDuration = Date.now() - startTime;
            totalFindings += retryResult.findings;
            allResults[step.functionName] = retryResult.data;
            
            setWorkflow(prev => {
              if (!prev) return null;
              const newSteps = [...prev.steps];
              newSteps[i] = { 
                ...newSteps[i], 
                status: 'success', 
                findings: retryResult.findings, 
                duration: retryDuration,
                error: undefined,
                data: retryResult.data
              };
              return { ...prev, steps: newSteps, totalFindings };
            });
          } catch (retryError) {
            // Keep as failed after retry
            console.error('Retry failed:', retryError);
          }
        }
      }
    }

    // Calculate severity counts from results
    const criticalCount = (allResults['webapp-scan']?.summary?.critical ?? 0) + 
                         (allResults['api-security']?.summary?.critical ?? 0) + 
                         (allResults['cloud-security']?.summary?.critical ?? 0);
    const highCount = (allResults['webapp-scan']?.summary?.high ?? 0) + 
                     (allResults['api-security']?.summary?.high ?? 0);

    // Create alert if critical findings
    if (criticalCount > 0 || totalFindings > 10) {
      await createAlert({
        type: 'workflow',
        severity: criticalCount > 0 ? 'critical' : 'high',
        title: `${workflow.name} Complete: ${totalFindings} findings on ${host}`,
        description: `Critical: ${criticalCount} | High: ${highCount} | Total: ${totalFindings}`,
        sourceModule: 'automated_workflow',
        target: host
      });
    }

    // Save comprehensive report
    await saveReport({
      module: 'automated_workflow',
      title: `${workflow.name} - ${host}`,
      summary: `Total: ${totalFindings} findings | ${workflow.steps.filter(s => s.status === 'success').length}/${workflow.steps.length} steps completed`,
      findings: allResults,
      severityCounts: {
        critical: criticalCount,
        high: highCount,
        medium: allResults['webapp-scan']?.summary?.medium ?? 0,
        low: allResults['webapp-scan']?.summary?.low ?? 0,
      },
    });

    setWorkflow(prev => prev ? { ...prev, status: 'completed', progress: 100, totalFindings } : null);
    toast({ 
      title: "Workflow Complete", 
      description: `${totalFindings} total findings across ${workflow.steps.filter(s => s.status === 'success').length} steps` 
    });
  };

  const pauseWorkflow = () => {
    setIsPaused(true);
    setWorkflow(prev => prev ? { ...prev, status: 'paused' } : null);
    toast({ title: "Workflow Paused" });
  };

  const stopWorkflow = () => {
    setIsPaused(true);
    setWorkflow(prev => prev ? { 
      ...prev, 
      status: 'idle', 
      progress: 0, 
      steps: prev.steps.map(s => ({ ...s, status: 'pending' as const, findings: undefined, duration: undefined, error: undefined })) 
    } : null);
    toast({ title: "Workflow Stopped" });
  };

  const exportResults = () => {
    if (!workflow) return;
    
    const report = {
      workflow: workflow.name,
      target: workflow.target,
      status: workflow.status,
      totalFindings: workflow.totalFindings,
      executedAt: new Date().toISOString(),
      steps: workflow.steps.map(s => ({
        name: s.name,
        module: s.module,
        status: s.status,
        findings: s.findings,
        duration: s.duration,
        data: s.data,
      }))
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${workflow.name.replace(/\s+/g, '-')}-${workflow.target}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'running': return <RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'skipped': return <ChevronRight className="h-4 w-4 text-muted-foreground" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getModuleColor = (module: string) => {
    const colors: Record<string, string> = {
      'recon': 'bg-cyan-500/10 text-cyan-500',
      'webapp': 'bg-purple-500/10 text-purple-500',
      'api-security': 'bg-blue-500/10 text-blue-500',
      'vuln': 'bg-orange-500/10 text-orange-500',
      'cloud-security': 'bg-green-500/10 text-green-500',
      'iam-security': 'bg-amber-500/10 text-amber-500',
      'autonomous': 'bg-red-500/10 text-red-500',
      'report': 'bg-gray-500/10 text-gray-500'
    };
    return colors[module] || 'bg-gray-500/10 text-gray-500';
  };

  return (
    <Card className="p-6 bg-card/50 backdrop-blur border-primary/20">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-lg">
          <Zap className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h2 className="text-xl font-bold">Automated Workflow</h2>
          <p className="text-sm text-muted-foreground">Real security testing with live module execution</p>
        </div>
      </div>

      {!workflow && (
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Workflow Template</label>
            <Select value={selectedWorkflow} onValueChange={setSelectedWorkflow}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PRESET_WORKFLOWS.map((w) => (
                  <SelectItem key={w.id} value={w.id}>
                    {w.name} - {w.steps.length} steps
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground mt-1">
              {PRESET_WORKFLOWS.find(w => w.id === selectedWorkflow)?.description}
            </p>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Target</label>
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com or example.com"
            />
          </div>

          <div className="flex items-center gap-2">
            <Switch checked={autoRetry} onCheckedChange={setAutoRetry} />
            <span className="text-sm">Auto-Retry on Failure</span>
          </div>

          <Button onClick={initializeWorkflow} className="w-full gap-2">
            <Settings className="h-4 w-4" />
            Initialize Workflow
          </Button>
        </div>
      )}

      {workflow && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold">{workflow.name}</h3>
              <p className="text-xs text-muted-foreground">Target: {workflow.target}</p>
            </div>
            <div className="flex gap-2">
              {workflow.status === 'idle' && (
                <Button onClick={executeWorkflow} className="gap-2">
                  <Play className="h-4 w-4" />
                  Start
                </Button>
              )}
              {workflow.status === 'running' && (
                <>
                  <Button onClick={pauseWorkflow} variant="outline" className="gap-2">
                    <Pause className="h-4 w-4" />
                    Pause
                  </Button>
                  <Button onClick={stopWorkflow} variant="destructive" className="gap-2">
                    <Square className="h-4 w-4" />
                    Stop
                  </Button>
                </>
              )}
              {workflow.status === 'paused' && (
                <Button onClick={executeWorkflow} className="gap-2">
                  <Play className="h-4 w-4" />
                  Resume
                </Button>
              )}
              {workflow.status === 'completed' && (
                <>
                  <Button onClick={exportResults} variant="outline" className="gap-2">
                    <Download className="h-4 w-4" />
                    Export
                  </Button>
                  <Button onClick={() => setWorkflow(null)} variant="outline" className="gap-2">
                    <RefreshCw className="h-4 w-4" />
                    New
                  </Button>
                </>
              )}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Progress</span>
              <span className="text-sm text-muted-foreground">
                {workflow.progress.toFixed(0)}% • {workflow.totalFindings || 0} findings
              </span>
            </div>
            <Progress value={workflow.progress} className="h-2" />
          </div>

          <ScrollArea className="h-[300px]">
            <div className="space-y-2">
              {workflow.steps.map((step, idx) => (
                <div
                  key={step.id}
                  className={`p-3 rounded border transition-all ${
                    step.status === 'running' ? 'border-blue-500 bg-blue-500/5 shadow-lg shadow-blue-500/10' :
                    step.status === 'success' ? 'border-green-500/30 bg-green-500/5' :
                    step.status === 'failed' ? 'border-red-500/30 bg-red-500/5' :
                    'border-border/50 bg-background/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground w-6">#{idx + 1}</span>
                      {getStatusIcon(step.status)}
                      <span className="font-medium">{step.name}</span>
                      <Badge className={getModuleColor(step.module)} variant="outline">
                        {step.module}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      {step.findings !== undefined && step.findings > 0 && (
                        <Badge variant={step.findings > 5 ? "destructive" : "secondary"}>
                          {step.findings} findings
                        </Badge>
                      )}
                      {step.duration && (
                        <span>{(step.duration / 1000).toFixed(1)}s</span>
                      )}
                    </div>
                  </div>
                  {step.error && (
                    <p className="text-xs text-red-500 mt-1 ml-9">{step.error}</p>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>

          {workflow.status === 'completed' && (
            <div className="p-4 bg-green-500/10 border border-green-500/30 rounded">
              <div className="flex items-center gap-2 text-green-500 mb-2">
                <CheckCircle className="h-5 w-5" />
                <span className="font-semibold">Workflow Completed</span>
              </div>
              <p className="text-sm text-muted-foreground">
                Total findings: {workflow.totalFindings} across {workflow.steps.filter(s => s.status === 'success').length} successful steps.
                Report saved to Security Reports.
              </p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

export default AutomatedWorkflow;
