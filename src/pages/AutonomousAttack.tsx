import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useToast } from "@/components/ui/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { ArrowLeft, Brain, Zap, Target, Activity, Shield, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function AutonomousAttack() {
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [attackChain, setAttackChain] = useState<any>(null);
  const [currentPhase, setCurrentPhase] = useState("");
  const { toast } = useToast();
  const navigate = useNavigate();

  const startAutonomousAttack = async () => {
    if (!target || !objective) {
      toast({
        title: "Missing Information",
        description: "Please provide both target and objective",
        variant: "destructive",
      });
      return;
    }

    setIsRunning(true);
    setCurrentPhase("Planning attack chain...");

    try {
      const { data, error } = await supabase.functions.invoke("autonomous-attack", {
        body: { target, objective, mode: "autonomous" },
      });

      if (error) throw error;

      if (data.success) {
        setAttackChain(data.attackChain);
        toast({
          title: "Autonomous Attack Completed",
          description: `Found ${data.summary.findings} vulnerabilities across ${data.summary.stepsExecuted} steps`,
        });
      } else {
        throw new Error(data.error || "Attack failed");
      }
    } catch (error: any) {
      console.error("Autonomous attack error:", error);
      toast({
        title: "Attack Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
      setCurrentPhase("");
    }
  };

  const startZAPScan = async () => {
    if (!target) {
      toast({
        title: "Missing Target",
        description: "Please provide a target URL",
        variant: "destructive",
      });
      return;
    }

    setIsRunning(true);
    setCurrentPhase("Initializing ZAP-style comprehensive scan...");

    try {
      const { data, error } = await supabase.functions.invoke("zap-scanner", {
        body: { 
          target, 
          scanDepth: "standard",
          includeAuth: true 
        },
      });

      if (error) throw error;

      if (data.success) {
        setAttackChain({
          ...data.scan,
          isZAPScan: true,
          summary: data.summary
        });
        toast({
          title: "ZAP Scan Completed",
          description: `Detected ${data.summary.vulnerabilitiesBySeversity.critical} critical, ${data.summary.vulnerabilitiesBySeversity.high} high vulnerabilities`,
        });
      } else {
        throw new Error(data.error || "Scan failed");
      }
    } catch (error: any) {
      console.error("ZAP scan error:", error);
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
      setCurrentPhase("");
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const getStepStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-green-500';
      case 'failed': return 'text-red-500';
      case 'running': return 'text-yellow-500';
      default: return 'text-gray-500';
    }
  };

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              onClick={() => navigate("/")}
              className="gap-2"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Dashboard
            </Button>
            <div>
              <h1 className="text-4xl font-bold flex items-center gap-3">
                <Brain className="w-10 h-10 text-primary" />
                Autonomous Attack Engine
              </h1>
              <p className="text-muted-foreground mt-2">
                AI-powered autonomous penetration testing with self-learning capabilities
              </p>
            </div>
          </div>
        </div>

        <Tabs defaultValue="autonomous" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="autonomous" className="gap-2">
              <Brain className="w-4 h-4" />
              Autonomous Attack Chain
            </TabsTrigger>
            <TabsTrigger value="zap" className="gap-2">
              <Zap className="w-4 h-4" />
              ZAP-Style Comprehensive Scan
            </TabsTrigger>
          </TabsList>

          <TabsContent value="autonomous" className="space-y-6">
            <Card className="p-6 bg-card/50 backdrop-blur border-primary/20">
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Target</label>
                  <Input
                    placeholder="example.com or 192.168.1.1"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isRunning}
                  />
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Attack Objective</label>
                  <Input
                    placeholder="Find all web vulnerabilities, test authentication, enumerate subdomains..."
                    value={objective}
                    onChange={(e) => setObjective(e.target.value)}
                    disabled={isRunning}
                  />
                </div>

                <Button
                  onClick={startAutonomousAttack}
                  disabled={isRunning || !target || !objective}
                  className="w-full gap-2"
                  size="lg"
                >
                  {isRunning ? (
                    <>
                      <Activity className="w-5 h-5 animate-spin" />
                      {currentPhase || "Executing..."}
                    </>
                  ) : (
                    <>
                      <Target className="w-5 h-5" />
                      Launch Autonomous Attack
                    </>
                  )}
                </Button>
              </div>
            </Card>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card className="p-4 bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-blue-500/20">
                <div className="flex items-center gap-3">
                  <Brain className="w-8 h-8 text-blue-400" />
                  <div>
                    <p className="text-sm text-muted-foreground">AI Planning</p>
                    <p className="text-2xl font-bold">Multi-Step</p>
                  </div>
                </div>
              </Card>

              <Card className="p-4 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/20">
                <div className="flex items-center gap-3">
                  <Zap className="w-8 h-8 text-purple-400" />
                  <div>
                    <p className="text-sm text-muted-foreground">Auto-Execution</p>
                    <p className="text-2xl font-bold">Adaptive</p>
                  </div>
                </div>
              </Card>

              <Card className="p-4 bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/20">
                <div className="flex items-center gap-3">
                  <Shield className="w-8 h-8 text-green-400" />
                  <div>
                    <p className="text-sm text-muted-foreground">Self-Learning</p>
                    <p className="text-2xl font-bold">Evolving</p>
                  </div>
                </div>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="zap" className="space-y-6">
            <Card className="p-6 bg-card/50 backdrop-blur border-primary/20">
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Target URL</label>
                  <Input
                    placeholder="https://example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isRunning}
                  />
                </div>

                <Button
                  onClick={startZAPScan}
                  disabled={isRunning || !target}
                  className="w-full gap-2"
                  size="lg"
                >
                  {isRunning ? (
                    <>
                      <Activity className="w-5 h-5 animate-spin" />
                      {currentPhase || "Scanning..."}
                    </>
                  ) : (
                    <>
                      <Zap className="w-5 h-5" />
                      Start Comprehensive Scan
                    </>
                  )}
                </Button>
              </div>
            </Card>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card className="p-4 bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border-cyan-500/20">
                <p className="text-sm text-muted-foreground mb-1">Spider/Crawl</p>
                <p className="text-xl font-bold">Traditional + AJAX</p>
              </Card>

              <Card className="p-4 bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border-indigo-500/20">
                <p className="text-sm text-muted-foreground mb-1">Passive Scan</p>
                <p className="text-xl font-bold">Headers & Config</p>
              </Card>

              <Card className="p-4 bg-gradient-to-br from-orange-500/10 to-red-500/10 border-orange-500/20">
                <p className="text-sm text-muted-foreground mb-1">Active Scan</p>
                <p className="text-xl font-bold">OWASP Top 10</p>
              </Card>

              <Card className="p-4 bg-gradient-to-br from-green-500/10 to-teal-500/10 border-green-500/20">
                <p className="text-sm text-muted-foreground mb-1">Auth Testing</p>
                <p className="text-xl font-bold">Session Security</p>
              </Card>
            </div>
          </TabsContent>
        </Tabs>

        {attackChain && (
          <div className="space-y-6">
            <Card className="p-6 bg-card/50 backdrop-blur">
              <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
                <Shield className="w-6 h-6" />
                {attackChain.isZAPScan ? 'Scan Results' : 'Attack Chain Results'}
              </h2>

              {attackChain.isZAPScan ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center">
                      <p className="text-3xl font-bold text-red-500">
                        {attackChain.summary?.vulnerabilitiesBySeversity?.critical || 0}
                      </p>
                      <p className="text-sm text-muted-foreground">Critical</p>
                    </div>
                    <div className="text-center">
                      <p className="text-3xl font-bold text-orange-500">
                        {attackChain.summary?.vulnerabilitiesBySeversity?.high || 0}
                      </p>
                      <p className="text-sm text-muted-foreground">High</p>
                    </div>
                    <div className="text-center">
                      <p className="text-3xl font-bold text-yellow-500">
                        {attackChain.summary?.vulnerabilitiesBySeversity?.medium || 0}
                      </p>
                      <p className="text-sm text-muted-foreground">Medium</p>
                    </div>
                    <div className="text-center">
                      <p className="text-3xl font-bold text-blue-500">
                        {attackChain.summary?.vulnerabilitiesBySeversity?.low || 0}
                      </p>
                      <p className="text-sm text-muted-foreground">Low</p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="text-xl font-semibold">Scan Phases</h3>
                    {Object.entries(attackChain.phases || {}).map(([key, phase]: [string, any]) => (
                      <Card key={key} className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold">{phase.name}</h4>
                          <Badge variant={phase.status === 'completed' ? 'default' : 'secondary'}>
                            {phase.status}
                          </Badge>
                        </div>
                        {phase.findings?.length > 0 && (
                          <div className="mt-2 space-y-2">
                            {phase.findings.map((finding: any, idx: number) => (
                              <div key={idx} className="text-sm p-2 bg-muted/30 rounded">
                                <div className="flex items-center gap-2">
                                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                                  <span className="font-medium">{finding.type || finding.name}</span>
                                  <Badge variant={getSeverityColor(finding.severity)}>
                                    {finding.severity}
                                  </Badge>
                                </div>
                                {finding.description && (
                                  <p className="mt-1 text-muted-foreground">{finding.description}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </Card>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Progress</p>
                      <p className="text-2xl font-bold">
                        {attackChain.currentStep} / {attackChain.steps?.length || 0} steps
                      </p>
                    </div>
                    <Badge variant="outline" className="text-lg px-4 py-2">
                      {attackChain.status}
                    </Badge>
                  </div>

                  <Progress 
                    value={(attackChain.currentStep / (attackChain.steps?.length || 1)) * 100} 
                    className="h-2"
                  />

                  <div className="space-y-3">
                    {attackChain.steps?.map((step: any) => (
                      <Card key={step.step} className="p-4">
                        <div className="flex items-start gap-3">
                          <div className={`text-2xl font-bold ${getStepStatusColor(step.status)}`}>
                            #{step.step}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-2">
                              <p className="font-semibold">{step.action}</p>
                              <Badge variant="outline">{step.tool}</Badge>
                            </div>
                            {step.error && (
                              <div className="text-sm text-red-500 mb-2">
                                ❌ {step.error}
                              </div>
                            )}
                            {step.learnings && (
                              <div className="text-sm text-blue-400 bg-blue-500/10 p-2 rounded">
                                🧠 {step.learnings}
                              </div>
                            )}
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>

                  {attackChain.findings?.length > 0 && (
                    <div className="mt-6">
                      <h3 className="text-xl font-semibold mb-4">Vulnerabilities Discovered</h3>
                      <div className="space-y-3">
                        {attackChain.findings.map((finding: any, idx: number) => (
                          <Card key={idx} className="p-4 bg-red-500/10 border-red-500/20">
                            <div className="flex items-center gap-2 mb-2">
                              <AlertTriangle className="w-5 h-5 text-red-500" />
                              <span className="font-semibold">{finding.type}</span>
                              <Badge variant={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">{finding.description}</p>
                          </Card>
                        ))}
                      </div>
                    </div>
                  )}

                  {attackChain.learnings?.length > 0 && (
                    <div className="mt-6">
                      <h3 className="text-xl font-semibold mb-4">AI Learnings</h3>
                      <div className="space-y-2">
                        {attackChain.learnings.map((learning: string, idx: number) => (
                          <div key={idx} className="text-sm p-3 bg-blue-500/10 rounded border border-blue-500/20">
                            💡 {learning}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}