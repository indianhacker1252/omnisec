import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { 
  Activity, 
  Cpu, 
  HardDrive, 
  Network, 
  Clock,
  TrendingUp,
  Zap,
  Brain
} from "lucide-react";

interface PerformanceMetrics {
  cpu: number;
  memory: number;
  network: number;
  latency: number;
  aiLearningProgress: number;
  scansCompleted: number;
  vulnerabilitiesFound: number;
  accuracy: number;
}

interface ScanHistory {
  timestamp: string;
  type: string;
  duration: number;
  findings: number;
}

export const PerformanceDashboard = () => {
  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    cpu: 35,
    memory: 48,
    network: 85,
    latency: 45,
    aiLearningProgress: 72,
    scansCompleted: 156,
    vulnerabilitiesFound: 423,
    accuracy: 94.5
  });

  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([
    { timestamp: "2024-01-15 14:32", type: "Web Scan", duration: 245, findings: 12 },
    { timestamp: "2024-01-15 13:15", type: "Network Recon", duration: 180, findings: 8 },
    { timestamp: "2024-01-15 11:45", type: "Vuln Assessment", duration: 320, findings: 15 },
    { timestamp: "2024-01-15 10:20", type: "Port Scan", duration: 95, findings: 24 },
    { timestamp: "2024-01-15 09:00", type: "LLM Red Team", duration: 420, findings: 6 }
  ]);

  const [isLive, setIsLive] = useState(true);

  // Simulate live metrics updates
  useEffect(() => {
    if (!isLive) return;
    
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        cpu: Math.max(10, Math.min(95, prev.cpu + (Math.random() - 0.5) * 10)),
        memory: Math.max(20, Math.min(90, prev.memory + (Math.random() - 0.5) * 5)),
        network: Math.max(50, Math.min(100, prev.network + (Math.random() - 0.5) * 8)),
        latency: Math.max(20, Math.min(200, prev.latency + (Math.random() - 0.5) * 20)),
        aiLearningProgress: Math.min(100, prev.aiLearningProgress + Math.random() * 0.1)
      }));
    }, 2000);

    return () => clearInterval(interval);
  }, [isLive]);

  const getStatusColor = (value: number, thresholds: { low: number; high: number }) => {
    if (value < thresholds.low) return "text-green-500";
    if (value < thresholds.high) return "text-yellow-500";
    return "text-red-500";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="h-6 w-6 text-cyber-purple" />
          <h2 className="text-xl font-bold font-mono">Performance Dashboard</h2>
        </div>
        <Badge 
          variant={isLive ? "default" : "secondary"}
          className={isLive ? "bg-green-500 animate-pulse" : ""}
          onClick={() => setIsLive(!isLive)}
          style={{ cursor: "pointer" }}
        >
          {isLive ? "● LIVE" : "○ PAUSED"}
        </Badge>
      </div>

      {/* System Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Cpu className="h-4 w-4 text-muted-foreground" />
              <span className={`text-xl font-bold ${getStatusColor(metrics.cpu, { low: 50, high: 80 })}`}>
                {metrics.cpu.toFixed(0)}%
              </span>
            </div>
            <Progress value={metrics.cpu} className="h-1.5" />
            <p className="text-xs text-muted-foreground mt-1">CPU Usage</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <HardDrive className="h-4 w-4 text-muted-foreground" />
              <span className={`text-xl font-bold ${getStatusColor(metrics.memory, { low: 60, high: 85 })}`}>
                {metrics.memory.toFixed(0)}%
              </span>
            </div>
            <Progress value={metrics.memory} className="h-1.5" />
            <p className="text-xs text-muted-foreground mt-1">Memory</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Network className="h-4 w-4 text-muted-foreground" />
              <span className="text-xl font-bold text-cyber-cyan">
                {metrics.network.toFixed(0)}%
              </span>
            </div>
            <Progress value={metrics.network} className="h-1.5" />
            <p className="text-xs text-muted-foreground mt-1">Network</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <span className={`text-xl font-bold ${getStatusColor(metrics.latency, { low: 100, high: 150 })}`}>
                {metrics.latency.toFixed(0)}ms
              </span>
            </div>
            <Progress value={100 - (metrics.latency / 2)} className="h-1.5" />
            <p className="text-xs text-muted-foreground mt-1">Latency</p>
          </CardContent>
        </Card>
      </div>

      {/* AI Learning & Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Brain className="h-4 w-4 text-cyber-purple" />
              AI Learning Mode
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Learning Progress</span>
                <span className="text-sm font-mono">{metrics.aiLearningProgress.toFixed(1)}%</span>
              </div>
              <Progress value={metrics.aiLearningProgress} className="h-2" />
              <div className="grid grid-cols-3 gap-2 pt-2">
                <div className="text-center">
                  <p className="text-lg font-bold text-cyber-cyan">{metrics.scansCompleted}</p>
                  <p className="text-xs text-muted-foreground">Scans</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold text-cyber-purple">{metrics.vulnerabilitiesFound}</p>
                  <p className="text-xs text-muted-foreground">Vulns Found</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold text-green-500">{metrics.accuracy}%</p>
                  <p className="text-xs text-muted-foreground">Accuracy</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-cyber-cyan" />
              Recent Scan Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {scanHistory.slice(0, 4).map((scan, idx) => (
                <div key={idx} className="flex items-center justify-between text-sm py-1 border-b border-border/30 last:border-0">
                  <div className="flex items-center gap-2">
                    <Zap className="h-3 w-3 text-cyber-purple" />
                    <span className="font-mono text-xs">{scan.type}</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>{scan.duration}s</span>
                    <Badge variant="outline" className="text-xs">
                      {scan.findings} findings
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
