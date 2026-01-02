import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useToast } from "@/components/ui/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { ArrowLeft, Brain, Zap, Target, Activity, Shield, AlertTriangle, Layers, BarChart3 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AttackSurfaceMapper } from "@/components/AttackSurfaceMapper";
import { PayloadEngine } from "@/components/PayloadEngine";
import { LearningFeedback } from "@/components/LearningFeedback";
import { ExplainableAI } from "@/components/ExplainableAI";
import { SafetyControls } from "@/components/SafetyControls";
import { AnalyticsDashboard } from "@/components/AnalyticsDashboard";
import { StrategyOrchestrator } from "@/components/StrategyOrchestrator";
import { ReportGenerator } from "@/components/ReportGenerator";

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
      toast({ title: "Missing Information", description: "Please provide both target and objective", variant: "destructive" });
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
        toast({ title: "Autonomous Attack Completed", description: `Found ${data.summary.findings} vulnerabilities across ${data.summary.stepsExecuted} steps` });
      } else {
        throw new Error(data.error || "Attack failed");
      }
    } catch (error: any) {
      console.error("Autonomous attack error:", error);
      toast({ title: "Attack Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsRunning(false);
      setCurrentPhase("");
    }
  };

  const startZAPScan = async () => {
    if (!target) {
      toast({ title: "Missing Target", description: "Please provide a target URL", variant: "destructive" });
      return;
    }
    setIsRunning(true);
    setCurrentPhase("Initializing ZAP-style comprehensive scan...");
    try {
      const { data, error } = await supabase.functions.invoke("zap-scanner", {
        body: { target, scanDepth: "standard", includeAuth: true },
      });
      if (error) throw error;
      if (data.success) {
        setAttackChain({ ...data.scan, isZAPScan: true, summary: data.summary });
        toast({ title: "ZAP Scan Completed", description: `Detected ${data.summary.vulnerabilitiesBySeversity.critical} critical, ${data.summary.vulnerabilitiesBySeversity.high} high vulnerabilities` });
      } else {
        throw new Error(data.error || "Scan failed");
      }
    } catch (error: any) {
      console.error("ZAP scan error:", error);
      toast({ title: "Scan Failed", description: error.message, variant: "destructive" });
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
      default: return 'text-muted-foreground';
    }
  };

  return (
    <div className="min-h-screen bg-background p-4 md:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => navigate("/")} className="gap-2">
              <ArrowLeft className="w-4 h-4" />
              Back
            </Button>
            <div>
              <h1 className="text-3xl font-bold flex items-center gap-3">
                <Brain className="w-8 h-8 text-primary" />
                Autonomous Attack Engine
              </h1>
              <p className="text-muted-foreground text-sm">AI-powered autonomous penetration testing with self-learning</p>
            </div>
          </div>
        </div>

        {/* Main Tabs */}
        <Tabs defaultValue="attack" className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="attack" className="gap-2"><Brain className="w-4 h-4" />Attack</TabsTrigger>
            <TabsTrigger value="surface" className="gap-2"><Target className="w-4 h-4" />Surface</TabsTrigger>
            <TabsTrigger value="tools" className="gap-2"><Zap className="w-4 h-4" />Tools</TabsTrigger>
            <TabsTrigger value="analytics" className="gap-2"><BarChart3 className="w-4 h-4" />Analytics</TabsTrigger>
            <TabsTrigger value="controls" className="gap-2"><Shield className="w-4 h-4" />Controls</TabsTrigger>
          </TabsList>

          {/* Attack Tab */}
          <TabsContent value="attack" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Attack Configuration */}
              <Card className="p-6 bg-card/50 backdrop-blur border-primary/20 lg:col-span-2">
                <Tabs defaultValue="autonomous">
                  <TabsList className="grid w-full grid-cols-2 mb-4">
                    <TabsTrigger value="autonomous"><Brain className="w-4 h-4 mr-2" />Autonomous</TabsTrigger>
                    <TabsTrigger value="zap"><Zap className="w-4 h-4 mr-2" />ZAP Scan</TabsTrigger>
                  </TabsList>
                  <TabsContent value="autonomous" className="space-y-4">
                    <Input placeholder="example.com or 192.168.1.1" value={target} onChange={(e) => setTarget(e.target.value)} disabled={isRunning} />
                    <Input placeholder="Find all web vulnerabilities, test authentication..." value={objective} onChange={(e) => setObjective(e.target.value)} disabled={isRunning} />
                    <Button onClick={startAutonomousAttack} disabled={isRunning || !target || !objective} className="w-full gap-2" size="lg">
                      {isRunning ? <><Activity className="w-5 h-5 animate-spin" />{currentPhase}</> : <><Target className="w-5 h-5" />Launch Autonomous Attack</>}
                    </Button>
                  </TabsContent>
                  <TabsContent value="zap" className="space-y-4">
                    <Input placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)} disabled={isRunning} />
                    <Button onClick={startZAPScan} disabled={isRunning || !target} className="w-full gap-2" size="lg">
                      {isRunning ? <><Activity className="w-5 h-5 animate-spin" />{currentPhase}</> : <><Zap className="w-5 h-5" />Start Comprehensive Scan</>}
                    </Button>
                  </TabsContent>
                </Tabs>
              </Card>

              {/* Strategy Orchestrator */}
              <StrategyOrchestrator />
            </div>

            {/* Attack Results */}
            {attackChain && (
              <Card className="p-6 bg-card/50 backdrop-blur">
                <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
                  <Shield className="w-6 h-6" />
                  {attackChain.isZAPScan ? 'Scan Results' : 'Attack Chain Results'}
                </h2>
                {attackChain.isZAPScan ? (
                  <div className="grid grid-cols-4 gap-4 mb-4">
                    {['critical', 'high', 'medium', 'low'].map(sev => (
                      <div key={sev} className="text-center">
                        <p className={`text-3xl font-bold ${sev === 'critical' ? 'text-red-500' : sev === 'high' ? 'text-orange-500' : sev === 'medium' ? 'text-yellow-500' : 'text-blue-500'}`}>
                          {attackChain.summary?.vulnerabilitiesBySeversity?.[sev] || 0}
                        </p>
                        <p className="text-sm text-muted-foreground capitalize">{sev}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="space-y-4">
                    <Progress value={(attackChain.currentStep / (attackChain.steps?.length || 1)) * 100} className="h-2" />
                    <div className="space-y-2">
                      {attackChain.steps?.slice(0, 5).map((step: any) => (
                        <div key={step.step} className="flex items-center gap-3 p-2 bg-background/50 rounded">
                          <span className={`font-bold ${getStepStatusColor(step.status)}`}>#{step.step}</span>
                          <span className="flex-1 text-sm">{step.action}</span>
                          <Badge variant="outline">{step.tool}</Badge>
                        </div>
                      ))}
                    </div>
                    {attackChain.findings?.length > 0 && (
                      <div className="mt-4">
                        <h3 className="font-semibold mb-2">Vulnerabilities Found: {attackChain.findings.length}</h3>
                        {attackChain.findings.slice(0, 3).map((f: any, i: number) => (
                          <Badge key={i} variant={getSeverityColor(f.severity)} className="mr-2">{f.type}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </Card>
            )}

            {/* Learning & Explainable AI */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <LearningFeedback />
              <ExplainableAI />
            </div>
          </TabsContent>

          {/* Surface Tab */}
          <TabsContent value="surface" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <AttackSurfaceMapper />
              <ReportGenerator target={target || "target.com"} />
            </div>
          </TabsContent>

          {/* Tools Tab */}
          <TabsContent value="tools" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <PayloadEngine />
              <StrategyOrchestrator />
            </div>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <AnalyticsDashboard />
          </TabsContent>

          {/* Controls Tab */}
          <TabsContent value="controls" className="space-y-6">
            <SafetyControls />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
