/**
 * OmniSec™ Blue Team Defense Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { useState, useEffect } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShieldCheck, Activity, AlertTriangle, TrendingUp, ArrowLeft, RefreshCw, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Alert {
  id: string;
  severity: string;
  technique: string;
  description: string;
  source: string;
  timestamp: string;
  ioc?: string;
}

interface Metrics {
  activeAlerts: number;
  threatsBlocked: number;
  socEfficiency: number;
  mttr: number;
  criticalAlerts: number;
  highAlerts: number;
}

const BlueTeamModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [mitreCoverage, setMitreCoverage] = useState<Record<string, number>>({});

  const fetchAlerts = async (action = "initial") => {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("blueteam-alerts", {
        body: { action }
      });

      if (error) throw error;

      if (data.alerts) setAlerts(data.alerts);
      if (data.metrics) setMetrics(data.metrics);
      if (data.mitreCoverage) setMitreCoverage(data.mitreCoverage);

      toast({
        title: "Alerts Updated",
        description: `Loaded ${data.alerts?.length || 0} security alerts`,
      });
    } catch (error) {
      console.error("Failed to fetch alerts:", error);
      toast({
        title: "Error",
        description: "Failed to fetch security alerts",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts("initial");
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-500";
      case "high": return "text-orange-500";
      case "medium": return "text-yellow-500";
      default: return "text-blue-500";
    }
  };

  const getSeverityBorder = (severity: string) => {
    switch (severity) {
      case "critical": return "rgb(239, 68, 68)";
      case "high": return "rgb(249, 115, 22)";
      case "medium": return "rgb(234, 179, 8)";
      default: return "rgb(59, 130, 246)";
    }
  };

  const displayMetrics = [
    { label: "Active Alerts", value: metrics?.activeAlerts?.toString() || "0", trend: `+${metrics?.criticalAlerts || 0} critical`, color: "text-red-500" },
    { label: "Threats Blocked", value: metrics?.threatsBlocked?.toLocaleString() || "0", trend: "+12%", color: "text-green-500" },
    { label: "SOC Efficiency", value: `${metrics?.socEfficiency || 0}%`, trend: "+2%", color: "text-cyan-500" },
    { label: "MTTR", value: `${metrics?.mttr || 0}min`, trend: "-3min", color: "text-green-500" },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center justify-between">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2 border-cyber-purple/30">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
          <Button 
            onClick={() => fetchAlerts("refresh")} 
            disabled={loading}
            className="gap-2"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Refresh Alerts
          </Button>
        </div>
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <ShieldCheck className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">Blue Team Defense</h1>
          </div>
          <p className="text-muted-foreground">
            Real-time threat detection, MITRE ATT&CK mapping, and SOC analytics
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {displayMetrics.map((metric) => (
            <Card key={metric.label} className="p-4 border-cyber-purple/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">{metric.label}</span>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono">{metric.value}</span>
                <span className={`text-xs font-medium ${metric.color}`}>
                  {metric.trend}
                </span>
              </div>
            </Card>
          ))}
        </div>

        <Tabs defaultValue="alerts" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="alerts">
              <AlertTriangle className="h-4 w-4 mr-2" />
              Active Alerts ({alerts.length})
            </TabsTrigger>
            <TabsTrigger value="mitre">
              <ShieldCheck className="h-4 w-4 mr-2" />
              MITRE ATT&CK
            </TabsTrigger>
            <TabsTrigger value="analytics">
              <TrendingUp className="h-4 w-4 mr-2" />
              Analytics
            </TabsTrigger>
          </TabsList>

          <TabsContent value="alerts" className="space-y-4">
            {loading && alerts.length === 0 ? (
              <Card className="p-8 text-center border-cyber-purple/30">
                <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-cyber-purple" />
                <p className="text-muted-foreground">Loading security alerts...</p>
              </Card>
            ) : alerts.length === 0 ? (
              <Card className="p-8 text-center border-cyber-purple/30">
                <ShieldCheck className="h-12 w-12 mx-auto mb-4 text-green-500" />
                <p className="text-muted-foreground">No active alerts. Systems secure.</p>
              </Card>
            ) : (
              alerts.map((alert) => (
                <Card
                  key={alert.id}
                  className="p-4 border-l-4 border-cyber-purple/30"
                  style={{ borderLeftColor: getSeverityBorder(alert.severity) }}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className={`h-5 w-5 ${getSeverityColor(alert.severity)}`} />
                      <Badge
                        variant="outline"
                        className={`uppercase border-current ${getSeverityColor(alert.severity)}`}
                      >
                        {alert.severity}
                      </Badge>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <h3 className="font-semibold mb-1 font-mono text-sm">
                    {alert.technique}
                  </h3>
                  <p className="text-sm text-muted-foreground mb-2">
                    {alert.description}
                  </p>
                  <div className="flex items-center gap-4 text-xs">
                    <Badge variant="secondary">{alert.source}</Badge>
                    {alert.ioc && (
                      <span className="font-mono text-muted-foreground">IOC: {alert.ioc}</span>
                    )}
                  </div>
                </Card>
              ))
            )}
          </TabsContent>

          <TabsContent value="mitre">
            <Card className="p-6 border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">
                MITRE ATT&CK Tactics Coverage
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {Object.entries(mitreCoverage).length > 0 ? (
                  Object.entries(mitreCoverage).map(([tactic, coverage]) => (
                    <Card
                      key={tactic}
                      className="p-4 text-center hover:bg-muted cursor-pointer transition-colors border-cyber-purple/30"
                    >
                      <div className="text-2xl font-bold text-cyber-purple mb-1">
                        {coverage}%
                      </div>
                      <div className="text-xs font-medium">{tactic}</div>
                    </Card>
                  ))
                ) : (
                  ["Initial Access", "Execution", "Persistence", "Privilege Escalation", 
                   "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                   "Collection", "Exfiltration"].map((tactic) => (
                    <Card
                      key={tactic}
                      className="p-4 text-center border-cyber-purple/30 animate-pulse"
                    >
                      <div className="text-2xl font-bold text-muted-foreground mb-1">--%</div>
                      <div className="text-xs font-medium">{tactic}</div>
                    </Card>
                  ))
                )}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="analytics">
            <Card className="p-6 border-cyber-purple/30">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Threat Distribution</h3>
                  <div className="space-y-3">
                    {[
                      { label: "Critical", count: metrics?.criticalAlerts || 0, color: "bg-red-500" },
                      { label: "High", count: metrics?.highAlerts || 0, color: "bg-orange-500" },
                      { label: "Medium", count: alerts.filter(a => a.severity === "medium").length, color: "bg-yellow-500" },
                      { label: "Low", count: alerts.filter(a => a.severity === "low").length, color: "bg-blue-500" },
                    ].map(item => (
                      <div key={item.label} className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${item.color}`} />
                        <span className="text-sm flex-1">{item.label}</span>
                        <span className="font-mono font-bold">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Top Sources</h3>
                  <div className="space-y-2">
                    {Array.from(new Set(alerts.map(a => a.source))).slice(0, 5).map(source => (
                      <Badge key={source} variant="secondary" className="mr-2 mb-2">
                        {source}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default BlueTeamModule;
