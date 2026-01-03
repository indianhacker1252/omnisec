/**
 * OmniSec™ AI Learning Engine
 * Centralized AI-powered learning for all security modules
 */

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import {
  Brain,
  Zap,
  Target,
  TrendingUp,
  Activity,
  Sparkles,
  Database,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  Clock
} from "lucide-react";

interface LearningMetric {
  id: string;
  metric: string;
  value: number;
  trend: 'up' | 'down' | 'stable';
  lastUpdated: string;
}

interface AttackPattern {
  id: string;
  name: string;
  category: string;
  effectiveness: number;
  lastUsed: string;
  successRate: number;
  mitreId: string;
}

interface PayloadTemplate {
  id: string;
  type: string;
  payload: string;
  successRate: number;
  adaptations: number;
  lastMutated: string;
}

export const AILearningEngine = () => {
  const { toast } = useToast();
  const [isLearning, setIsLearning] = useState(false);
  const [autoLearn, setAutoLearn] = useState(true);
  const [metrics, setMetrics] = useState<LearningMetric[]>([]);
  const [patterns, setPatterns] = useState<AttackPattern[]>([]);
  const [payloads, setPayloads] = useState<PayloadTemplate[]>([]);
  const [learningProgress, setLearningProgress] = useState(0);

  useEffect(() => {
    // Initialize with sample learning data
    setMetrics([
      { id: '1', metric: 'Overall Accuracy', value: 94.2, trend: 'up', lastUpdated: new Date().toISOString() },
      { id: '2', metric: 'False Positive Rate', value: 2.3, trend: 'down', lastUpdated: new Date().toISOString() },
      { id: '3', metric: 'Detection Speed', value: 98.7, trend: 'up', lastUpdated: new Date().toISOString() },
      { id: '4', metric: 'Payload Success Rate', value: 87.5, trend: 'up', lastUpdated: new Date().toISOString() },
      { id: '5', metric: 'Evasion Effectiveness', value: 91.3, trend: 'stable', lastUpdated: new Date().toISOString() }
    ]);

    setPatterns([
      { id: '1', name: 'SQL Injection Chain', category: 'injection', effectiveness: 92, lastUsed: new Date().toISOString(), successRate: 88, mitreId: 'T1190' },
      { id: '2', name: 'XSS DOM-based', category: 'xss', effectiveness: 87, lastUsed: new Date().toISOString(), successRate: 85, mitreId: 'T1059.007' },
      { id: '3', name: 'SSRF Cloud Metadata', category: 'ssrf', effectiveness: 95, lastUsed: new Date().toISOString(), successRate: 78, mitreId: 'T1552.005' },
      { id: '4', name: 'Auth Bypass JWT', category: 'auth', effectiveness: 89, lastUsed: new Date().toISOString(), successRate: 72, mitreId: 'T1078' },
      { id: '5', name: 'Deserialization RCE', category: 'deserialization', effectiveness: 96, lastUsed: new Date().toISOString(), successRate: 65, mitreId: 'T1203' }
    ]);

    setPayloads([
      { id: '1', type: 'SQLi', payload: "' OR 1=1--", successRate: 45, adaptations: 12, lastMutated: new Date().toISOString() },
      { id: '2', type: 'XSS', payload: '<img src=x onerror=alert(1)>', successRate: 62, adaptations: 8, lastMutated: new Date().toISOString() },
      { id: '3', type: 'SSTI', payload: '{{7*7}}', successRate: 78, adaptations: 5, lastMutated: new Date().toISOString() },
      { id: '4', type: 'Path Traversal', payload: '../../etc/passwd', successRate: 55, adaptations: 9, lastMutated: new Date().toISOString() }
    ]);
  }, []);

  const startLearningCycle = async () => {
    setIsLearning(true);
    setLearningProgress(0);

    // Simulate learning process
    for (let i = 0; i <= 100; i += 10) {
      await new Promise(r => setTimeout(r, 300));
      setLearningProgress(i);
    }

    // Update metrics after learning
    setMetrics(prev => prev.map(m => ({
      ...m,
      value: Math.min(100, m.value + (Math.random() * 2 - 0.5)),
      lastUpdated: new Date().toISOString()
    })));

    setIsLearning(false);
    toast({ title: "Learning Cycle Complete", description: "Models updated with latest patterns" });
  };

  const mutatePayload = (payloadId: string) => {
    setPayloads(prev => prev.map(p => {
      if (p.id === payloadId) {
        return {
          ...p,
          adaptations: p.adaptations + 1,
          successRate: Math.min(100, p.successRate + Math.random() * 5),
          lastMutated: new Date().toISOString()
        };
      }
      return p;
    }));
    toast({ title: "Payload Mutated", description: "Adaptive mutation applied" });
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-4 w-4 text-green-500" />;
      case 'down': return <TrendingUp className="h-4 w-4 text-red-500 rotate-180" />;
      default: return <Activity className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getEffectivenessColor = (value: number) => {
    if (value >= 90) return 'text-green-500';
    if (value >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 backdrop-blur border-primary/20">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Brain className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold">AI Learning Engine</h2>
            <p className="text-sm text-muted-foreground">Self-improving attack intelligence</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Auto-Learn</span>
            <Switch checked={autoLearn} onCheckedChange={setAutoLearn} />
          </div>
          <Button
            onClick={startLearningCycle}
            disabled={isLearning}
            variant="outline"
            className="gap-2"
          >
            {isLearning ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin" />
                Learning...
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4" />
                Train Models
              </>
            )}
          </Button>
        </div>
      </div>

      {isLearning && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">Learning Progress</span>
            <span className="text-sm text-muted-foreground">{learningProgress}%</span>
          </div>
          <Progress value={learningProgress} className="h-2" />
        </div>
      )}

      <Tabs defaultValue="metrics" className="w-full">
        <TabsList className="grid w-full grid-cols-3 mb-4">
          <TabsTrigger value="metrics" className="gap-2">
            <TrendingUp className="h-4 w-4" />
            Metrics
          </TabsTrigger>
          <TabsTrigger value="patterns" className="gap-2">
            <Target className="h-4 w-4" />
            Patterns
          </TabsTrigger>
          <TabsTrigger value="payloads" className="gap-2">
            <Zap className="h-4 w-4" />
            Payloads
          </TabsTrigger>
        </TabsList>

        <TabsContent value="metrics">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {metrics.map((metric) => (
              <Card key={metric.id} className="p-4 bg-background/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{metric.metric}</span>
                  {getTrendIcon(metric.trend)}
                </div>
                <div className="flex items-baseline gap-2">
                  <span className={`text-2xl font-bold ${getEffectivenessColor(metric.value)}`}>
                    {metric.value.toFixed(1)}%
                  </span>
                </div>
                <div className="flex items-center gap-1 mt-2 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  Updated {new Date(metric.lastUpdated).toLocaleTimeString()}
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="patterns">
          <ScrollArea className="h-[300px]">
            <div className="space-y-3">
              {patterns.map((pattern) => (
                <Card key={pattern.id} className="p-4 bg-background/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4 text-primary" />
                      <span className="font-medium">{pattern.name}</span>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant="outline">{pattern.mitreId}</Badge>
                      <Badge variant="secondary">{pattern.category}</Badge>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>Effectiveness: <span className={getEffectivenessColor(pattern.effectiveness)}>{pattern.effectiveness}%</span></span>
                      <span>Success: {pattern.successRate}%</span>
                    </div>
                    <Button size="sm" variant="ghost">
                      <Zap className="h-3 w-3 mr-1" />
                      Use
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="payloads">
          <ScrollArea className="h-[300px]">
            <div className="space-y-3">
              {payloads.map((payload) => (
                <Card key={payload.id} className="p-4 bg-background/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{payload.type}</Badge>
                      <span className="text-sm font-medium">Adaptations: {payload.adaptations}</span>
                    </div>
                    <span className={`text-sm font-bold ${getEffectivenessColor(payload.successRate)}`}>
                      {payload.successRate.toFixed(1)}% success
                    </span>
                  </div>
                  <code className="block text-xs bg-muted/50 p-2 rounded font-mono mb-2 break-all">
                    {payload.payload}
                  </code>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">
                      Last mutated: {new Date(payload.lastMutated).toLocaleString()}
                    </span>
                    <Button size="sm" variant="ghost" onClick={() => mutatePayload(payload.id)}>
                      <RefreshCw className="h-3 w-3 mr-1" />
                      Mutate
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </Card>
  );
};

export default AILearningEngine;
