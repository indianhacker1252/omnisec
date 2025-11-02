/**
 * OmniSec™ AI Threat Intelligence Engine
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - ML-Powered Threat Detection
 */

import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Brain, TrendingUp, Activity, AlertTriangle, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

const AIThreatModule = () => {
  const navigate = useNavigate();
  const anomalies = [
    {
      timestamp: new Date().toISOString(),
      type: "Behavioral Anomaly",
      confidence: 94,
      description: "Unusual data exfiltration pattern detected",
      severity: "high",
    },
    {
      timestamp: new Date().toISOString(),
      type: "Network Anomaly",
      confidence: 87,
      description: "Suspicious outbound connections to known malicious IPs",
      severity: "critical",
    },
    {
      timestamp: new Date().toISOString(),
      type: "Authentication Anomaly",
      confidence: 76,
      description: "Login from geographically impossible location",
      severity: "medium",
    },
  ];

  const predictions = [
    { threat: "Ransomware Attack", probability: 23, trend: "increasing" },
    { threat: "Data Breach", probability: 18, trend: "stable" },
    { threat: "DDoS Attack", probability: 12, trend: "decreasing" },
    { threat: "Insider Threat", probability: 8, trend: "increasing" },
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
            <Brain className="h-8 w-8 text-cyber-purple" />
            <h1 className="text-3xl font-bold font-mono">AI Threat Intelligence Engine</h1>
          </div>
          <p className="text-muted-foreground">
            Machine learning-driven anomaly detection and predictive threat analysis
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">ML Models Active</span>
              <Brain className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono">7</div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">Anomalies Detected</span>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono text-red-500">23</div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">Detection Accuracy</span>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono text-green-500">96.4%</div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">False Positives</span>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono">3.2%</div>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              Real-time Anomaly Detection
            </h3>
            <div className="space-y-3">
              {anomalies.map((anomaly, idx) => (
                <Card
                  key={idx}
                  className={`p-4 border-l-4 ${
                    anomaly.severity === "critical"
                      ? "border-red-500"
                      : anomaly.severity === "high"
                      ? "border-orange-500"
                      : "border-yellow-500"
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <Badge
                      variant={
                        anomaly.severity === "critical" || anomaly.severity === "high"
                          ? "destructive"
                          : "secondary"
                      }
                    >
                      {anomaly.type}
                    </Badge>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground">Confidence</div>
                      <div className="font-bold text-sm">{anomaly.confidence}%</div>
                    </div>
                  </div>
                  <p className="text-sm mb-1">{anomaly.description}</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(anomaly.timestamp).toLocaleString()}
                  </p>
                </Card>
              ))}
            </div>
          </Card>

          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Brain className="h-5 w-5 text-cyber-purple" />
              Predictive Threat Analysis
            </h3>
            <div className="space-y-4">
              {predictions.map((pred, idx) => (
                <div key={idx}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{pred.threat}</span>
                      <Badge
                        variant="outline"
                        className={
                          pred.trend === "increasing"
                            ? "border-red-500 text-red-500"
                            : pred.trend === "decreasing"
                            ? "border-green-500 text-green-500"
                            : "border-gray-500 text-gray-500"
                        }
                      >
                        {pred.trend}
                      </Badge>
                    </div>
                    <span className="font-bold font-mono">{pred.probability}%</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        pred.probability > 20
                          ? "bg-red-500"
                          : pred.probability > 10
                          ? "bg-yellow-500"
                          : "bg-green-500"
                      }`}
                      style={{ width: `${pred.probability}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <Card className="mt-6 p-4 bg-muted/50">
              <h4 className="font-semibold text-sm mb-2">Active ML Models</h4>
              <div className="space-y-1 text-xs">
                <div className="flex justify-between">
                  <span>Neural Network (Deep Learning)</span>
                  <Badge variant="secondary">Active</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Random Forest Classifier</span>
                  <Badge variant="secondary">Active</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Isolation Forest (Anomaly)</span>
                  <Badge variant="secondary">Active</Badge>
                </div>
                <div className="flex justify-between">
                  <span>LSTM (Time Series)</span>
                  <Badge variant="secondary">Active</Badge>
                </div>
              </div>
            </Card>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default AIThreatModule;
