import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Activity, 
  Cpu, 
  HardDrive, 
  Network, 
  Clock,
  TrendingUp,
  Zap,
  Brain,
  Bell,
  X,
  CheckCircle2,
  AlertTriangle,
  AlertCircle
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface Alert {
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  source_module: string;
  is_read: boolean;
  is_cleared: boolean;
  created_at: string;
}

interface ScanHistoryItem {
  id: string;
  module: string;
  scan_type: string;
  target: string;
  status: string;
  duration_ms: number;
  findings_count: number;
  created_at: string;
}

export const PerformanceDashboard = () => {
  const { toast } = useToast();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [isLive, setIsLive] = useState(true);
  const [stats, setStats] = useState({
    totalScans: 0,
    totalFindings: 0,
    activeAlerts: 0
  });

  // Fetch alerts and scan history
  const fetchData = async () => {
    try {
      // Fetch active alerts (not cleared)
      const { data: alertsData, error: alertsError } = await supabase
        .from('security_alerts')
        .select('*')
        .eq('is_cleared', false)
        .order('created_at', { ascending: false })
        .limit(10);

      if (alertsError) {
        console.error('Error fetching alerts:', alertsError);
      } else {
        setAlerts(alertsData || []);
      }

      // Fetch recent scan history
      const { data: historyData, error: historyError } = await supabase
        .from('scan_history')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (historyError) {
        console.error('Error fetching history:', historyError);
      } else {
        setScanHistory(historyData || []);
      }

      // Calculate stats
      const { count: totalScans } = await supabase
        .from('scan_history')
        .select('*', { count: 'exact', head: true });

      const { data: findingsData } = await supabase
        .from('scan_history')
        .select('findings_count');

      const totalFindings = findingsData?.reduce((sum, item) => sum + (item.findings_count || 0), 0) || 0;

      setStats({
        totalScans: totalScans || 0,
        totalFindings,
        activeAlerts: (alertsData || []).length
      });

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Subscribe to realtime updates
    const alertsChannel = supabase
      .channel('alerts-changes')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'security_alerts' }, () => {
        fetchData();
      })
      .subscribe();

    const historyChannel = supabase
      .channel('history-changes')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'scan_history' }, () => {
        fetchData();
      })
      .subscribe();

    // Refresh interval if live
    const interval = isLive ? setInterval(fetchData, 30000) : null;

    return () => {
      alertsChannel.unsubscribe();
      historyChannel.unsubscribe();
      if (interval) clearInterval(interval);
    };
  }, [isLive]);

  const clearAlert = async (alertId: string) => {
    try {
      const { error } = await supabase
        .from('security_alerts')
        .update({ is_cleared: true, cleared_at: new Date().toISOString() })
        .eq('id', alertId);

      if (error) throw error;

      setAlerts(prev => prev.filter(a => a.id !== alertId));
      toast({ title: "Alert cleared" });
    } catch (error) {
      console.error('Error clearing alert:', error);
      toast({ title: "Failed to clear alert", variant: "destructive" });
    }
  };

  const clearAllAlerts = async () => {
    try {
      const { error } = await supabase
        .from('security_alerts')
        .update({ is_cleared: true, cleared_at: new Date().toISOString() })
        .eq('is_cleared', false);

      if (error) throw error;

      setAlerts([]);
      toast({ title: "All alerts cleared" });
    } catch (error) {
      console.error('Error clearing alerts:', error);
      toast({ title: "Failed to clear alerts", variant: "destructive" });
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'high': return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'medium': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <CheckCircle2 className="h-4 w-4 text-blue-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
    }
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
          className={isLive ? "bg-green-500 animate-pulse cursor-pointer" : "cursor-pointer"}
          onClick={() => setIsLive(!isLive)}
        >
          {isLive ? "● LIVE" : "○ PAUSED"}
        </Badge>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Zap className="h-4 w-4 text-muted-foreground" />
              <span className="text-xl font-bold text-cyber-cyan">{stats.totalScans}</span>
            </div>
            <p className="text-xs text-muted-foreground">Total Scans</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Brain className="h-4 w-4 text-muted-foreground" />
              <span className="text-xl font-bold text-cyber-purple">{stats.totalFindings}</span>
            </div>
            <p className="text-xs text-muted-foreground">Total Findings</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Bell className="h-4 w-4 text-muted-foreground" />
              <span className={`text-xl font-bold ${stats.activeAlerts > 0 ? 'text-orange-500' : 'text-green-500'}`}>
                {stats.activeAlerts}
              </span>
            </div>
            <p className="text-xs text-muted-foreground">Active Alerts</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <span className="text-xl font-bold text-green-500">Online</span>
            </div>
            <p className="text-xs text-muted-foreground">System Status</p>
          </CardContent>
        </Card>
      </div>

      {/* Alerts & History */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Active Alerts */}
        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Bell className="h-4 w-4 text-cyber-purple" />
                Active Alerts
              </CardTitle>
              {alerts.length > 0 && (
                <Button variant="ghost" size="sm" onClick={clearAllAlerts} className="text-xs">
                  Clear All
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading alerts...</p>
            ) : alerts.length === 0 ? (
              <div className="text-center py-4">
                <CheckCircle2 className="h-8 w-8 mx-auto text-green-500 mb-2" />
                <p className="text-sm text-muted-foreground">No active alerts</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {alerts.map((alert) => (
                  <div key={alert.id} className="flex items-start justify-between p-2 bg-background/50 rounded border border-border/50">
                    <div className="flex items-start gap-2">
                      {getSeverityIcon(alert.severity)}
                      <div>
                        <p className="text-sm font-medium">{alert.title}</p>
                        <p className="text-xs text-muted-foreground">{alert.source_module}</p>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => clearAlert(alert.id)}>
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scan History */}
        <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-cyber-cyan" />
              Recent Scan Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading history...</p>
            ) : scanHistory.length === 0 ? (
              <div className="text-center py-4">
                <Activity className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No scans recorded yet</p>
                <p className="text-xs text-muted-foreground">Run a scan to see activity here</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {scanHistory.slice(0, 5).map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between text-sm py-2 border-b border-border/30 last:border-0">
                    <div className="flex items-center gap-2">
                      <Zap className="h-3 w-3 text-cyber-purple" />
                      <div>
                        <span className="font-mono text-xs">{scan.scan_type}</span>
                        <p className="text-xs text-muted-foreground">{scan.module}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <Badge variant="outline" className={scan.status === 'completed' ? 'text-green-500' : 'text-yellow-500'}>
                        {scan.status}
                      </Badge>
                      {scan.findings_count > 0 && (
                        <Badge variant="outline">{scan.findings_count} findings</Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};