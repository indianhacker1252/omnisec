import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { 
  Brain, 
  MessageSquare,
  Lightbulb,
  Target,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  Sparkles
} from "lucide-react";

interface DecisionTrace {
  id: string;
  action: string;
  reasoning: string;
  confidence: number;
  factors: { name: string; weight: number; value: string }[];
  outcome: 'success' | 'failure' | 'pending';
}

interface AIExplanation {
  vulnerability: string;
  whyTested: string;
  featureContributions: { feature: string; contribution: number }[];
  attackSummary: string;
  recommendations: string[];
}

export const ExplainableAI = () => {
  const [traces] = useState<DecisionTrace[]>([
    {
      id: '1',
      action: 'XSS Test on /api/search',
      reasoning: 'Input parameter "q" reflects in response without sanitization. DOM context detected.',
      confidence: 85,
      factors: [
        { name: 'Input Reflection', weight: 0.4, value: 'Detected' },
        { name: 'WAF Presence', weight: 0.2, value: 'Not Detected' },
        { name: 'Content-Type', weight: 0.2, value: 'text/html' },
        { name: 'Similar Past Success', weight: 0.2, value: '73% success rate' }
      ],
      outcome: 'success'
    },
    {
      id: '2',
      action: 'SQL Injection on /api/users',
      reasoning: 'Numeric ID parameter with database error messages. Potential time-based blind SQLi.',
      confidence: 62,
      factors: [
        { name: 'Error Messages', weight: 0.3, value: 'SQL syntax error visible' },
        { name: 'Parameter Type', weight: 0.25, value: 'Numeric' },
        { name: 'Database Type', weight: 0.25, value: 'MySQL detected' },
        { name: 'Rate Limiting', weight: 0.2, value: 'Active - caution needed' }
      ],
      outcome: 'pending'
    },
    {
      id: '3',
      action: 'Auth Bypass on /admin',
      reasoning: 'JWT token validation may be weak. Algorithm confusion attack attempted.',
      confidence: 45,
      factors: [
        { name: 'Token Type', weight: 0.3, value: 'JWT detected' },
        { name: 'Algorithm', weight: 0.3, value: 'HS256' },
        { name: 'Key Exposure', weight: 0.2, value: 'Not found' },
        { name: 'History', weight: 0.2, value: '28% success on similar' }
      ],
      outcome: 'failure'
    }
  ]);

  const [explanation] = useState<AIExplanation>({
    vulnerability: 'Reflected XSS in Search Endpoint',
    whyTested: 'The search parameter "q" was identified during attack surface mapping as a user-controlled input that reflects directly in the HTML response. Historical data shows 78% of similar parameters are vulnerable to XSS when no WAF is detected.',
    featureContributions: [
      { feature: 'Input reflects in response', contribution: 35 },
      { feature: 'No Content-Security-Policy', contribution: 25 },
      { feature: 'No WAF detected', contribution: 20 },
      { feature: 'HTML context (not attribute)', contribution: 15 },
      { feature: 'Past success on similar targets', contribution: 5 }
    ],
    attackSummary: 'The attacker can inject malicious JavaScript through the search parameter. When a victim visits a crafted URL, the script executes in their browser context, potentially stealing session cookies, performing actions on their behalf, or redirecting to phishing sites.',
    recommendations: [
      'Implement output encoding using context-aware escaping',
      'Add Content-Security-Policy header with strict-dynamic',
      'Use HTTPOnly flag on session cookies',
      'Consider implementing a Web Application Firewall'
    ]
  });

  const getOutcomeIcon = (outcome: string) => {
    switch (outcome) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failure': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: return <HelpCircle className="h-4 w-4 text-yellow-500" />;
    }
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="h-5 w-5 text-cyber-purple" />
          Explainable AI
          <Badge variant="outline" className="ml-auto">
            <Sparkles className="h-3 w-3 mr-1" />
            Professional Grade
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Decision Traces */}
        <div>
          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <MessageSquare className="h-4 w-4" />
            Decision Trace
          </h4>
          <Accordion type="single" collapsible>
            {traces.map((trace) => (
              <AccordionItem key={trace.id} value={trace.id}>
                <AccordionTrigger className="hover:no-underline">
                  <div className="flex items-center gap-2 text-left">
                    {getOutcomeIcon(trace.outcome)}
                    <span className="text-sm">{trace.action}</span>
                    <Badge variant="outline" className="ml-2">{trace.confidence}%</Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-3 pt-2">
                    <p className="text-sm text-muted-foreground">{trace.reasoning}</p>
                    <div className="grid grid-cols-2 gap-2">
                      {trace.factors.map((factor, idx) => (
                        <div key={idx} className="p-2 bg-background/50 rounded text-xs">
                          <div className="flex justify-between mb-1">
                            <span className="font-medium">{factor.name}</span>
                            <span className="text-muted-foreground">{(factor.weight * 100).toFixed(0)}%</span>
                          </div>
                          <span className="text-cyber-cyan">{factor.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>

        {/* Feature Contributions */}
        <div>
          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Target className="h-4 w-4" />
            Feature Contribution Analysis
          </h4>
          <div className="space-y-2">
            {explanation.featureContributions.map((fc, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <div className="flex-1 h-6 bg-background/50 rounded overflow-hidden">
                  <div 
                    className="h-full bg-cyber-purple/50 flex items-center px-2"
                    style={{ width: `${fc.contribution}%` }}
                  >
                    <span className="text-xs truncate">{fc.feature}</span>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground w-10 text-right">{fc.contribution}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Human-Readable Summary */}
        <div className="p-3 bg-cyber-cyan/10 rounded border border-cyber-cyan/30">
          <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
            <Lightbulb className="h-4 w-4 text-cyber-cyan" />
            Attack Summary (Human-Readable)
          </h4>
          <p className="text-xs text-muted-foreground mb-3">{explanation.attackSummary}</p>
          <div className="space-y-1">
            <p className="text-xs font-semibold">Recommendations:</p>
            <ul className="text-xs text-muted-foreground list-disc list-inside">
              {explanation.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
