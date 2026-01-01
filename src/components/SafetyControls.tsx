import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  AlertOctagon,
  StopCircle,
  RotateCcw,
  FileText,
  Lock,
  Eye,
  Clock,
  CheckCircle,
  XCircle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface SafetyControl {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  type: 'safety' | 'ethics' | 'control';
}

interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  result: 'success' | 'blocked' | 'warning';
  reason?: string;
}

export const SafetyControls = () => {
  const { toast } = useToast();
  const [killSwitchActive, setKillSwitchActive] = useState(false);
  const [safetyScore, setSafetyScore] = useState(92);

  const [controls, setControls] = useState<SafetyControl[]>([
    { id: '1', name: 'Rate Limiting', description: 'Enforce request rate limits to prevent detection', enabled: true, type: 'safety' },
    { id: '2', name: 'Scope Enforcement', description: 'Block actions outside authorized scope', enabled: true, type: 'safety' },
    { id: '3', name: 'Human-like Behavior', description: 'Randomize timing and patterns', enabled: true, type: 'safety' },
    { id: '4', name: 'WAF Awareness', description: 'Detect and respect WAF boundaries', enabled: true, type: 'safety' },
    { id: '5', name: 'Policy Compliance', description: 'Check bug bounty program rules', enabled: true, type: 'ethics' },
    { id: '6', name: 'Consent Verification', description: 'Verify target authorization', enabled: true, type: 'ethics' },
    { id: '7', name: 'Data Redaction', description: 'Auto-redact sensitive data in reports', enabled: true, type: 'ethics' },
    { id: '8', name: 'Deterministic Replay', description: 'Enable scan reproducibility', enabled: false, type: 'control' },
    { id: '9', name: 'Offline Mode', description: 'No external connections for sensitive tests', enabled: false, type: 'control' },
  ]);

  const [auditLog] = useState<AuditLogEntry[]>([
    { id: '1', timestamp: new Date().toISOString(), action: 'XSS Test', target: 'example.com/search', result: 'success', reason: '' },
    { id: '2', timestamp: new Date(Date.now() - 60000).toISOString(), action: 'SQLi Test', target: 'out-of-scope.com', result: 'blocked', reason: 'Target not in authorized scope' },
    { id: '3', timestamp: new Date(Date.now() - 120000).toISOString(), action: 'Port Scan', target: '192.168.1.1', result: 'warning', reason: 'Rate limit approaching' },
    { id: '4', timestamp: new Date(Date.now() - 180000).toISOString(), action: 'Auth Bypass', target: 'example.com/admin', result: 'success', reason: '' },
  ]);

  const toggleControl = (id: string) => {
    setControls(prev => prev.map(c => 
      c.id === id ? { ...c, enabled: !c.enabled } : c
    ));
    
    // Update safety score
    const enabledCount = controls.filter(c => c.enabled).length;
    setSafetyScore(Math.round((enabledCount / controls.length) * 100));
  };

  const activateKillSwitch = () => {
    setKillSwitchActive(true);
    toast({
      title: "🛑 Emergency Kill Switch Activated",
      description: "All scanning operations have been halted.",
      variant: "destructive"
    });
  };

  const resetKillSwitch = () => {
    setKillSwitchActive(false);
    toast({
      title: "System Resumed",
      description: "Operations can continue."
    });
  };

  const getResultIcon = (result: string) => {
    switch (result) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'blocked': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <AlertOctagon className="h-4 w-4 text-yellow-500" />;
    }
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-cyber-red/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-cyber-red" />
          Safety & Control Center
          <Badge variant={safetyScore >= 80 ? "default" : "destructive"} className="ml-auto">
            Safety Score: {safetyScore}%
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Kill Switch */}
        <div className={`p-4 rounded border-2 ${killSwitchActive ? 'bg-red-500/20 border-red-500' : 'bg-background/50 border-border'}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <StopCircle className={`h-8 w-8 ${killSwitchActive ? 'text-red-500 animate-pulse' : 'text-muted-foreground'}`} />
              <div>
                <h4 className="font-semibold">Emergency Kill Switch</h4>
                <p className="text-xs text-muted-foreground">Immediately halt all operations</p>
              </div>
            </div>
            {killSwitchActive ? (
              <Button variant="outline" onClick={resetKillSwitch}>
                <RotateCcw className="h-4 w-4 mr-2" />
                Reset
              </Button>
            ) : (
              <Button variant="destructive" onClick={activateKillSwitch}>
                <StopCircle className="h-4 w-4 mr-2" />
                Activate
              </Button>
            )}
          </div>
        </div>

        {/* Safety Controls */}
        <div>
          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Lock className="h-4 w-4" />
            Safety Controls
          </h4>
          <div className="space-y-2">
            {controls.map((control) => (
              <div key={control.id} className="flex items-center justify-between p-2 bg-background/50 rounded border border-border/50">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">
                    {control.type}
                  </Badge>
                  <div>
                    <p className="text-sm font-medium">{control.name}</p>
                    <p className="text-xs text-muted-foreground">{control.description}</p>
                  </div>
                </div>
                <Switch
                  checked={control.enabled}
                  onCheckedChange={() => toggleControl(control.id)}
                  disabled={killSwitchActive}
                />
              </div>
            ))}
          </div>
        </div>

        {/* Audit Log */}
        <div>
          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Audit Log
          </h4>
          <ScrollArea className="h-40">
            <div className="space-y-2">
              {auditLog.map((entry) => (
                <div key={entry.id} className="flex items-center justify-between p-2 bg-background/50 rounded border border-border/50">
                  <div className="flex items-center gap-2">
                    {getResultIcon(entry.result)}
                    <div>
                      <p className="text-sm font-medium">{entry.action}</p>
                      <p className="text-xs text-muted-foreground truncate max-w-[200px]">{entry.target}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <Badge variant={entry.result === 'success' ? 'default' : entry.result === 'blocked' ? 'destructive' : 'secondary'}>
                      {entry.result}
                    </Badge>
                    <p className="text-xs text-muted-foreground mt-1">
                      <Clock className="h-3 w-3 inline mr-1" />
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
};
