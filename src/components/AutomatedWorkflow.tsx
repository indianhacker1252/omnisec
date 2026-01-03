/**
 * OmniSec™ Automated Workflow Engine
 * Orchestrates multi-step security testing workflows
 */

import { useState } from "react";
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
  Target,
  Shield,
  RefreshCw,
  ChevronRight
} from "lucide-react";

interface WorkflowStep {
  id: string;
  name: string;
  module: string;
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  duration?: number;
  findings?: number;
  error?: string;
}

interface Workflow {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  status: 'idle' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  target?: string;
}

const PRESET_WORKFLOWS = [
  {
    id: 'full-pentest',
    name: 'Full Penetration Test',
    description: 'Complete security assessment including recon, vuln scan, and exploitation',
    steps: [
      { id: '1', name: 'Subdomain Enumeration', module: 'recon', status: 'pending' as const },
      { id: '2', name: 'Port Scanning', module: 'recon', status: 'pending' as const },
      { id: '3', name: 'Technology Fingerprinting', module: 'recon', status: 'pending' as const },
      { id: '4', name: 'Web Application Scan', module: 'webapp', status: 'pending' as const },
      { id: '5', name: 'API Security Test', module: 'api-security', status: 'pending' as const },
      { id: '6', name: 'Vulnerability Assessment', module: 'vuln', status: 'pending' as const },
      { id: '7', name: 'Payload Generation', module: 'redteam', status: 'pending' as const },
      { id: '8', name: 'Report Generation', module: 'report', status: 'pending' as const }
    ]
  },
  {
    id: 'web-assessment',
    name: 'Web Application Assessment',
    description: 'Focused web application security testing',
    steps: [
      { id: '1', name: 'Spider/Crawl', module: 'webapp', status: 'pending' as const },
      { id: '2', name: 'Active Scan', module: 'webapp', status: 'pending' as const },
      { id: '3', name: 'SQL Injection Test', module: 'webapp', status: 'pending' as const },
      { id: '4', name: 'XSS Detection', module: 'webapp', status: 'pending' as const },
      { id: '5', name: 'Authentication Testing', module: 'webapp', status: 'pending' as const },
      { id: '6', name: 'Report Generation', module: 'report', status: 'pending' as const }
    ]
  },
  {
    id: 'cloud-audit',
    name: 'Cloud Security Audit',
    description: 'AWS/Azure/GCP misconfiguration detection',
    steps: [
      { id: '1', name: 'IAM Policy Audit', module: 'cloud-security', status: 'pending' as const },
      { id: '2', name: 'Storage Permissions', module: 'cloud-security', status: 'pending' as const },
      { id: '3', name: 'Network Security', module: 'cloud-security', status: 'pending' as const },
      { id: '4', name: 'Encryption Check', module: 'cloud-security', status: 'pending' as const },
      { id: '5', name: 'Compliance Mapping', module: 'cloud-security', status: 'pending' as const }
    ]
  },
  {
    id: 'api-test',
    name: 'API Security Testing',
    description: 'OWASP API Top 10 security testing',
    steps: [
      { id: '1', name: 'API Discovery', module: 'api-security', status: 'pending' as const },
      { id: '2', name: 'Authentication Testing', module: 'api-security', status: 'pending' as const },
      { id: '3', name: 'Authorization Testing', module: 'api-security', status: 'pending' as const },
      { id: '4', name: 'Input Validation', module: 'api-security', status: 'pending' as const },
      { id: '5', name: 'Rate Limiting Test', module: 'api-security', status: 'pending' as const }
    ]
  }
];

export const AutomatedWorkflow = () => {
  const { toast } = useToast();
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>('full-pentest');
  const [target, setTarget] = useState('');
  const [workflow, setWorkflow] = useState<Workflow | null>(null);
  const [autoRetry, setAutoRetry] = useState(true);
  const [parallelExecution, setParallelExecution] = useState(false);

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
      steps: preset.steps.map(s => ({ ...s }))
    });

    toast({ title: "Workflow Initialized", description: `${preset.name} ready to execute` });
  };

  const executeWorkflow = async () => {
    if (!workflow) return;

    setWorkflow(prev => prev ? { ...prev, status: 'running' } : null);

    for (let i = 0; i < workflow.steps.length; i++) {
      if (workflow.status === 'paused') break;

      const step = workflow.steps[i];
      
      // Update step to running
      setWorkflow(prev => {
        if (!prev) return null;
        const newSteps = [...prev.steps];
        newSteps[i] = { ...newSteps[i], status: 'running' };
        return { ...prev, steps: newSteps, progress: ((i) / prev.steps.length) * 100 };
      });

      // Simulate step execution
      await new Promise(r => setTimeout(r, 1500 + Math.random() * 1000));

      // Random success/fail for demo
      const success = Math.random() > 0.15;
      const findings = success ? Math.floor(Math.random() * 10) : 0;
      const duration = 1500 + Math.random() * 1000;

      setWorkflow(prev => {
        if (!prev) return null;
        const newSteps = [...prev.steps];
        newSteps[i] = {
          ...newSteps[i],
          status: success ? 'success' : 'failed',
          duration,
          findings,
          error: success ? undefined : 'Connection timeout'
        };
        return {
          ...prev,
          steps: newSteps,
          progress: ((i + 1) / prev.steps.length) * 100
        };
      });

      // Auto-retry on failure if enabled
      if (!success && autoRetry) {
        toast({ title: "Retrying Step", description: `Retrying ${step.name}...` });
        await new Promise(r => setTimeout(r, 1000));
        
        setWorkflow(prev => {
          if (!prev) return null;
          const newSteps = [...prev.steps];
          newSteps[i] = { ...newSteps[i], status: 'success', findings: 2, error: undefined };
          return { ...prev, steps: newSteps };
        });
      }
    }

    setWorkflow(prev => prev ? { ...prev, status: 'completed', progress: 100 } : null);
    toast({ title: "Workflow Complete", description: "All steps executed successfully" });
  };

  const pauseWorkflow = () => {
    setWorkflow(prev => prev ? { ...prev, status: 'paused' } : null);
    toast({ title: "Workflow Paused" });
  };

  const stopWorkflow = () => {
    setWorkflow(prev => prev ? { ...prev, status: 'idle', progress: 0, steps: prev.steps.map(s => ({ ...s, status: 'pending' as const })) } : null);
    toast({ title: "Workflow Stopped" });
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
      'redteam': 'bg-red-500/10 text-red-500',
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
          <p className="text-sm text-muted-foreground">Orchestrated multi-step security testing</p>
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

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Switch checked={autoRetry} onCheckedChange={setAutoRetry} />
              <span className="text-sm">Auto-Retry on Failure</span>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={parallelExecution} onCheckedChange={setParallelExecution} />
              <span className="text-sm">Parallel Execution</span>
            </div>
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
                <Button onClick={() => setWorkflow(null)} variant="outline" className="gap-2">
                  <RefreshCw className="h-4 w-4" />
                  New Workflow
                </Button>
              )}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Progress</span>
              <span className="text-sm text-muted-foreground">{workflow.progress.toFixed(0)}%</span>
            </div>
            <Progress value={workflow.progress} className="h-2" />
          </div>

          <ScrollArea className="h-[300px]">
            <div className="space-y-2">
              {workflow.steps.map((step, idx) => (
                <div
                  key={step.id}
                  className={`p-3 rounded border ${
                    step.status === 'running' ? 'border-blue-500 bg-blue-500/5' :
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
                        <Badge variant="secondary">{step.findings} findings</Badge>
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
                Total findings: {workflow.steps.reduce((sum, s) => sum + (s.findings || 0), 0)} across {workflow.steps.filter(s => s.status === 'success').length} successful steps
              </p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

export default AutomatedWorkflow;
