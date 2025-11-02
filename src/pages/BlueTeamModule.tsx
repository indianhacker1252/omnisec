/**
 * OmniSec™ Blue Team Defense Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShieldCheck, Activity, AlertTriangle, TrendingUp, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

const BlueTeamModule = () => {
  const navigate = useNavigate();
  const alerts = [
    {
      id: 1,
      severity: "critical",
      technique: "T1566.001 - Phishing: Spearphishing Attachment",
      description: "Suspicious email attachment detected",
      source: "Email Gateway",
      timestamp: new Date().toISOString(),
    },
    {
      id: 2,
      severity: "high",
      technique: "T1078 - Valid Accounts",
      description: "Multiple failed login attempts from unusual location",
      source: "IAM",
      timestamp: new Date().toISOString(),
    },
    {
      id: 3,
      severity: "medium",
      technique: "T1071.001 - Application Layer Protocol: Web",
      description: "Unusual outbound traffic pattern detected",
      source: "Network Monitor",
      timestamp: new Date().toISOString(),
    },
  ];

  const metrics = [
    { label: "Active Alerts", value: "23", trend: "+5", color: "text-red-500" },
    { label: "Threats Blocked", value: "1,247", trend: "+12%", color: "text-green-500" },
    { label: "SOC Efficiency", value: "94%", trend: "+2%", color: "text-cyan-500" },
    { label: "MTTR", value: "12min", trend: "-3min", color: "text-green-500" },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2">
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
            SIEM integration, MITRE ATT&CK mapping, and real-time threat detection
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {metrics.map((metric) => (
            <Card key={metric.label} className="p-4">
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
              Active Alerts
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
            {alerts.map((alert) => (
              <Card
                key={alert.id}
                className="p-4 border-l-4"
                style={{
                  borderLeftColor:
                    alert.severity === "critical"
                      ? "rgb(239, 68, 68)"
                      : alert.severity === "high"
                      ? "rgb(249, 115, 22)"
                      : "rgb(234, 179, 8)",
                }}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle
                      className={`h-5 w-5 ${
                        alert.severity === "critical"
                          ? "text-red-500"
                          : alert.severity === "high"
                          ? "text-orange-500"
                          : "text-yellow-500"
                      }`}
                    />
                    <Badge
                      variant="outline"
                      className={`uppercase ${
                        alert.severity === "critical"
                          ? "border-red-500 text-red-500"
                          : alert.severity === "high"
                          ? "border-orange-500 text-orange-500"
                          : "border-yellow-500 text-yellow-500"
                      }`}
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
                </div>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="mitre">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">
                MITRE ATT&CK Tactics Coverage
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {[
                  "Initial Access",
                  "Execution",
                  "Persistence",
                  "Privilege Escalation",
                  "Defense Evasion",
                  "Credential Access",
                  "Discovery",
                  "Lateral Movement",
                  "Collection",
                  "Exfiltration",
                ].map((tactic) => (
                  <Card
                    key={tactic}
                    className="p-4 text-center hover:bg-muted cursor-pointer transition-colors"
                  >
                    <div className="text-2xl font-bold text-cyber-purple mb-1">
                      {Math.floor(Math.random() * 30 + 70)}%
                    </div>
                    <div className="text-xs font-medium">{tactic}</div>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="analytics">
            <Card className="p-6 text-center border-dashed">
              <TrendingUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                Advanced analytics and threat intelligence dashboard coming soon
              </p>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default BlueTeamModule;
