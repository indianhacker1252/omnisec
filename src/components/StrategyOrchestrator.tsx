import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { 
  Layers, 
  Play, 
  Pause,
  SkipForward,
  RefreshCw,
  TrendingUp,
  Target,
  Zap,
  Brain
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Strategy {
  id: string;
  name: string;
  description: string;
  category: 'recon' | 'exploit' | 'post-exploit' | 'persistence';
  performanceScore: number;
  usageCount: number;
  successRate: number;
  enabled: boolean;
  priority: number;
}

interface StrategyOrchestrationProps {
  onStrategySelect?: (strategy: Strategy) => void;
}

export const StrategyOrchestrator = ({ onStrategySelect }: StrategyOrchestrationProps) => {
  const { toast } = useToast();
  const [activeStrategy, setActiveStrategy] = useState<string | null>(null);
  const [autoSwitch, setAutoSwitch] = useState(true);
  
  const [strategies, setStrategies] = useState<Strategy[]>([
    {
      id: 'recon-passive',
      name: 'Passive Reconnaissance',
      description: 'OSINT, DNS enumeration, certificate transparency',
      category: 'recon',
      performanceScore: 92,
      usageCount: 156,
      successRate: 88,
      enabled: true,
      priority: 1
    },
    {
      id: 'recon-active',
      name: 'Active Reconnaissance',
      description: 'Port scanning, service enumeration, banner grabbing',
      category: 'recon',
      performanceScore: 85,
      usageCount: 89,
      successRate: 76,
      enabled: true,
      priority: 2
    },
    {
      id: 'exploit-web',
      name: 'Web Application Exploitation',
      description: 'OWASP Top 10, XSS, SQLi, SSRF, CSRF testing',
      category: 'exploit',
      performanceScore: 78,
      usageCount: 234,
      successRate: 45,
      enabled: true,
      priority: 3
    },
    {
      id: 'exploit-api',
      name: 'API Security Testing',
      description: 'REST/GraphQL fuzzing, auth bypass, BOLA/BFLA',
      category: 'exploit',
      performanceScore: 71,
      usageCount: 112,
      successRate: 52,
      enabled: true,
      priority: 4
    },
    {
      id: 'exploit-auth',
      name: 'Authentication Bypass',
      description: 'JWT attacks, OAuth flaws, session hijacking',
      category: 'exploit',
      performanceScore: 65,
      usageCount: 67,
      successRate: 38,
      enabled: true,
      priority: 5
    },
    {
      id: 'post-lateral',
      name: 'Lateral Movement',
      description: 'Privilege escalation, pivoting, credential harvesting',
      category: 'post-exploit',
      performanceScore: 58,
      usageCount: 23,
      successRate: 62,
      enabled: false,
      priority: 6
    },
    {
      id: 'persist-backdoor',
      name: 'Persistence Mechanisms',
      description: 'Backdoor installation, scheduled tasks, registry',
      category: 'persistence',
      performanceScore: 45,
      usageCount: 8,
      successRate: 75,
      enabled: false,
      priority: 7
    }
  ]);

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'recon': return 'bg-blue-500/20 text-blue-400';
      case 'exploit': return 'bg-orange-500/20 text-orange-400';
      case 'post-exploit': return 'bg-purple-500/20 text-purple-400';
      case 'persistence': return 'bg-red-500/20 text-red-400';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const toggleStrategy = (id: string) => {
    setStrategies(prev => prev.map(s => 
      s.id === id ? { ...s, enabled: !s.enabled } : s
    ));
  };

  const executeStrategy = (strategy: Strategy) => {
    setActiveStrategy(strategy.id);
    onStrategySelect?.(strategy);
    toast({
      title: "Strategy Activated",
      description: `Executing: ${strategy.name}`
    });
  };

  const skipToNext = () => {
    const enabledStrategies = strategies.filter(s => s.enabled);
    const currentIndex = enabledStrategies.findIndex(s => s.id === activeStrategy);
    const nextStrategy = enabledStrategies[(currentIndex + 1) % enabledStrategies.length];
    if (nextStrategy) {
      executeStrategy(nextStrategy);
    }
  };

  const reorderByPerformance = () => {
    setStrategies(prev => [...prev].sort((a, b) => b.performanceScore - a.performanceScore));
    toast({ title: "Strategies reordered by performance" });
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-primary" />
            Strategy Orchestration
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Auto-Switch</span>
            <Switch checked={autoSwitch} onCheckedChange={setAutoSwitch} />
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Control Buttons */}
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={reorderByPerformance}>
            <TrendingUp className="h-4 w-4 mr-1" />
            Sort by Performance
          </Button>
          <Button size="sm" variant="outline" onClick={skipToNext} disabled={!activeStrategy}>
            <SkipForward className="h-4 w-4 mr-1" />
            Skip to Next
          </Button>
        </div>

        {/* Active Strategy */}
        {activeStrategy && (
          <div className="p-3 bg-primary/10 rounded-lg border border-primary/30">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-primary animate-pulse" />
                <span className="font-medium">Active: {strategies.find(s => s.id === activeStrategy)?.name}</span>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setActiveStrategy(null)}>
                <Pause className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        {/* Strategy List */}
        <ScrollArea className="h-72">
          <div className="space-y-2">
            {strategies.map((strategy) => (
              <div 
                key={strategy.id} 
                className={`p-3 rounded-lg border transition-all ${
                  activeStrategy === strategy.id 
                    ? 'bg-primary/20 border-primary' 
                    : 'bg-background/50 border-border/50 hover:border-primary/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Switch 
                      checked={strategy.enabled} 
                      onCheckedChange={() => toggleStrategy(strategy.id)}
                    />
                    <span className="font-medium text-sm">{strategy.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getCategoryColor(strategy.category)}>
                      {strategy.category}
                    </Badge>
                    <Button 
                      size="sm" 
                      variant="ghost"
                      onClick={() => executeStrategy(strategy)}
                      disabled={!strategy.enabled}
                    >
                      <Play className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{strategy.description}</p>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Performance</span>
                    <Progress value={strategy.performanceScore} className="h-1 mt-1" />
                    <span className="text-primary">{strategy.performanceScore}%</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Success Rate</span>
                    <Progress value={strategy.successRate} className="h-1 mt-1" />
                    <span className="text-primary">{strategy.successRate}%</span>
                  </div>
                  <div className="text-right">
                    <span className="text-muted-foreground">Used</span>
                    <p className="font-mono">{strategy.usageCount}x</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>

        {/* AI Learning Insight */}
        <div className="p-3 bg-secondary/20 rounded border border-secondary/30">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="h-4 w-4 text-secondary" />
            <span className="text-sm font-medium">AI Strategy Recommendation</span>
          </div>
          <p className="text-xs text-muted-foreground">
            Based on target profile, recommend starting with <strong>Passive Reconnaissance</strong> 
            followed by <strong>Web Application Exploitation</strong>. Historical success rate 
            on similar targets: 73%.
          </p>
        </div>
      </CardContent>
    </Card>
  );
};
