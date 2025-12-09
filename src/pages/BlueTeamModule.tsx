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
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShieldCheck, Activity, AlertTriangle, TrendingUp, ArrowLeft, Settings, ExternalLink, Server } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface SIEMConfig {
  endpoint: string;
  apiKey: string;
}

interface SupportedPlatform {
  name: string;
  endpoint: string;
}

const BlueTeamModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [needsConfig, setNeedsConfig] = useState(true);
  const [supportedPlatforms, setSupportedPlatforms] = useState<SupportedPlatform[]>([]);
  const [siemConfig, setSiemConfig] = useState<SIEMConfig>({ endpoint: "", apiKey: "" });
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    checkConfiguration();
  }, []);

  const checkConfiguration = async () => {
    try {
      const { data, error } = await supabase.functions.invoke("blueteam-alerts", {
        body: { action: "check" }
      });

      if (data?.error === "SIEM_NOT_CONFIGURED") {
        setNeedsConfig(true);
        setSupportedPlatforms(data.instructions?.supportedPlatforms || []);
      } else if (data?.success) {
        setNeedsConfig(false);
        setAlerts(data.alerts || []);
      }
    } catch (error) {
      console.error("Config check failed:", error);
    }
  };

  const connectSIEM = async () => {
    if (!siemConfig.endpoint || !siemConfig.apiKey) {
      toast({
        title: "Missing Configuration",
        description: "Please provide both SIEM endpoint and API key",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("blueteam-alerts", {
        body: { 
          action: "fetch",
          siemEndpoint: siemConfig.endpoint,
          apiKey: siemConfig.apiKey
        }
      });

      if (error) throw error;

      if (data?.success) {
        setNeedsConfig(false);
        setAlerts(data.alerts || []);
        toast({
          title: "SIEM Connected",
          description: `Fetched ${data.alerts?.length || 0} alerts from your SIEM`
        });
      } else {
        throw new Error(data?.message || "Failed to connect to SIEM");
      }
    } catch (error: any) {
      toast({
        title: "Connection Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-500";
      case "high": return "text-orange-500";
      case "medium": return "text-yellow-500";
      default: return "text-blue-500";
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2 border-cyber-purple/30">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
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

        {needsConfig ? (
          <div className="space-y-6">
            {/* Configuration Required Notice */}
            <Card className="p-6 bg-yellow-500/10 border-yellow-500/50">
              <div className="flex items-start gap-4">
                <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="font-semibold text-yellow-500 mb-2">SIEM Integration Required</h3>
                  <p className="text-sm text-muted-foreground">
                    The Blue Team module requires connection to your SIEM, log management platform, 
                    or security monitoring solution to display real security alerts. 
                    OmniSec does not generate simulated or fake alerts.
                  </p>
                </div>
              </div>
            </Card>

            {/* SIEM Configuration Form */}
            <Card className="p-6 border-cyber-purple/30">
              <div className="flex items-center gap-2 mb-4">
                <Settings className="h-5 w-5 text-cyber-purple" />
                <h3 className="text-lg font-semibold">Connect Your SIEM</h3>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium mb-2 block">SIEM API Endpoint</label>
                    <Input
                      placeholder="https://your-siem.com/api/alerts"
                      value={siemConfig.endpoint}
                      onChange={(e) => setSiemConfig(prev => ({ ...prev, endpoint: e.target.value }))}
                      className="font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium mb-2 block">API Key / Token</label>
                    <Input
                      type="password"
                      placeholder="Your SIEM API key"
                      value={siemConfig.apiKey}
                      onChange={(e) => setSiemConfig(prev => ({ ...prev, apiKey: e.target.value }))}
                      className="font-mono"
                    />
                  </div>
                  <Button 
                    onClick={connectSIEM} 
                    disabled={loading}
                    className="w-full bg-cyber-purple hover:bg-cyber-purple/80"
                  >
                    {loading ? "Connecting..." : "Connect SIEM"}
                  </Button>
                </div>

                <div>
                  <h4 className="font-medium mb-3">Supported Platforms</h4>
                  <div className="space-y-2">
                    {[
                      { name: "Splunk", desc: "REST API endpoint" },
                      { name: "Elastic SIEM", desc: "Security alerts endpoint" },
                      { name: "Microsoft Sentinel", desc: "Azure Security Center API" },
                      { name: "IBM QRadar", desc: "Offenses API" },
                      { name: "Wazuh", desc: "Security alerts API" },
                      { name: "TheHive", desc: "Alert API" },
                      { name: "CrowdStrike", desc: "Falcon API" },
                      { name: "SentinelOne", desc: "Threats API" }
                    ].map((platform) => (
                      <div key={platform.name} className="flex items-center justify-between p-2 rounded bg-muted/30">
                        <div className="flex items-center gap-2">
                          <Server className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm font-medium">{platform.name}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">{platform.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </Card>

            {/* Alternative Options */}
            <Card className="p-6 border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">Alternative Options</h3>
              <div className="grid md:grid-cols-3 gap-4">
                <Card className="p-4 border-dashed hover:border-cyber-cyan/50 cursor-pointer transition-colors">
                  <h4 className="font-medium mb-2">Log Analysis</h4>
                  <p className="text-sm text-muted-foreground">
                    Upload log files for offline analysis and threat hunting
                  </p>
                </Card>
                <Card className="p-4 border-dashed hover:border-cyber-cyan/50 cursor-pointer transition-colors">
                  <h4 className="font-medium mb-2">Syslog Receiver</h4>
                  <p className="text-sm text-muted-foreground">
                    Configure OmniSec agent to receive syslog data
                  </p>
                </Card>
                <Card 
                  className="p-4 border-dashed hover:border-cyber-cyan/50 cursor-pointer transition-colors"
                  onClick={() => navigate('/kali-integration')}
                >
                  <h4 className="font-medium mb-2">Kali Integration</h4>
                  <p className="text-sm text-muted-foreground">
                    Use local security tools for defense monitoring
                  </p>
                </Card>
              </div>
            </Card>
          </div>
        ) : (
          // Connected SIEM View
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
              {alerts.length === 0 ? (
                <Card className="p-8 text-center border-cyber-purple/30">
                  <ShieldCheck className="h-12 w-12 mx-auto mb-4 text-green-500" />
                  <p className="text-muted-foreground">No active alerts. Systems secure.</p>
                </Card>
              ) : (
                alerts.map((alert, idx) => (
                  <Card
                    key={idx}
                    className="p-4 border-l-4 border-cyber-purple/30"
                    style={{ borderLeftColor: alert.severity === "critical" ? "rgb(239, 68, 68)" : "rgb(249, 115, 22)" }}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className={`h-5 w-5 ${getSeverityColor(alert.severity)}`} />
                        <Badge variant="outline" className={`uppercase border-current ${getSeverityColor(alert.severity)}`}>
                          {alert.severity}
                        </Badge>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <h3 className="font-semibold mb-1 font-mono text-sm">{alert.title || alert.technique}</h3>
                    <p className="text-sm text-muted-foreground">{alert.description}</p>
                  </Card>
                ))
              )}
            </TabsContent>

            <TabsContent value="mitre">
              <Card className="p-6 text-center border-dashed border-cyber-purple/30">
                <Activity className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">
                  MITRE ATT&CK mapping requires alerts from connected SIEM
                </p>
              </Card>
            </TabsContent>

            <TabsContent value="analytics">
              <Card className="p-6 text-center border-dashed border-cyber-purple/30">
                <TrendingUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">
                  Analytics will be generated based on incoming SIEM data
                </p>
              </Card>
            </TabsContent>
          </Tabs>
        )}
      </main>
    </div>
  );
};

export default BlueTeamModule;
