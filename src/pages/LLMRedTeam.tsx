import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { 
  Brain, 
  Shield, 
  AlertTriangle, 
  Play, 
  FileText,
  CheckCircle,
  XCircle,
  Loader2,
  Target
} from "lucide-react";

interface TestResult {
  attack: string;
  vulnerable: boolean;
  response: string;
  severity: string;
}

interface CategoryResult {
  category: string;
  description: string;
  tests: TestResult[];
}

interface Summary {
  totalTests: number;
  vulnerableTests: number;
  criticalCount: number;
  highCount: number;
  securityScore: number;
  grade: string;
}

const CATEGORIES = [
  { id: "prompt_injection", name: "Prompt Injection", icon: "💉" },
  { id: "jailbreak", name: "Jailbreak Attempts", icon: "🔓" },
  { id: "pii_extraction", name: "PII Extraction", icon: "🔍" },
  { id: "data_leakage", name: "Data Leakage", icon: "💧" },
  { id: "harmful_content", name: "Harmful Content", icon: "☠️" },
  { id: "bias_detection", name: "Bias Detection", icon: "⚖️" },
  { id: "hallucination", name: "Hallucination", icon: "🌀" },
  { id: "context_manipulation", name: "Context Manipulation", icon: "🎭" }
];

const LLMRedTeam = () => {
  const { toast } = useToast();
  const [systemPrompt, setSystemPrompt] = useState("You are a helpful AI assistant for a cybersecurity platform.");
  const [selectedCategories, setSelectedCategories] = useState<string[]>(["prompt_injection", "jailbreak", "data_leakage"]);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<CategoryResult[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);

  const toggleCategory = (id: string) => {
    setSelectedCategories(prev => 
      prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]
    );
  };

  const runRedTeamTest = async () => {
    if (selectedCategories.length === 0) {
      toast({
        title: "No Categories Selected",
        description: "Please select at least one vulnerability category to test.",
        variant: "destructive"
      });
      return;
    }

    setIsRunning(true);
    setProgress(0);
    setResults([]);
    setSummary(null);

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 5, 90));
      }, 500);

      const { data, error } = await supabase.functions.invoke("llm-redteam", {
        body: {
          action: "run_test",
          targetPrompt: systemPrompt,
          categories: selectedCategories
        }
      });

      clearInterval(progressInterval);
      setProgress(100);

      if (error) throw error;

      setResults(data.results);
      setSummary(data.summary);

      toast({
        title: "Red Team Assessment Complete",
        description: `Security Score: ${data.summary.securityScore}/100 (Grade: ${data.summary.grade})`
      });
    } catch (error: any) {
      console.error("Red team test error:", error);
      toast({
        title: "Test Failed",
        description: error.message || "Failed to run red team assessment",
        variant: "destructive"
      });
    } finally {
      setIsRunning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-green-500";
      default: return "bg-gray-500";
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A": return "text-green-500";
      case "B": return "text-blue-500";
      case "C": return "text-yellow-500";
      case "D": return "text-orange-500";
      case "F": return "text-red-500";
      default: return "text-muted-foreground";
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="flex items-center gap-3 mb-6">
          <Brain className="h-8 w-8 text-cyber-purple" />
          <div>
            <h1 className="text-3xl font-bold font-mono">LLM Red Teaming</h1>
            <p className="text-muted-foreground">DeepTeam-inspired AI Security Assessment</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration Panel */}
          <div className="space-y-6">
            <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  Target Configuration
                </CardTitle>
                <CardDescription>Define the LLM system prompt to test</CardDescription>
              </CardHeader>
              <CardContent>
                <Textarea
                  value={systemPrompt}
                  onChange={(e) => setSystemPrompt(e.target.value)}
                  placeholder="Enter the system prompt you want to test..."
                  className="min-h-[150px] font-mono text-sm"
                />
              </CardContent>
            </Card>

            <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Vulnerability Categories
                </CardTitle>
                <CardDescription>Select tests to run</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {CATEGORIES.map((cat) => (
                  <div key={cat.id} className="flex items-center space-x-3">
                    <Checkbox
                      id={cat.id}
                      checked={selectedCategories.includes(cat.id)}
                      onCheckedChange={() => toggleCategory(cat.id)}
                    />
                    <label htmlFor={cat.id} className="flex items-center gap-2 cursor-pointer text-sm">
                      <span>{cat.icon}</span>
                      <span>{cat.name}</span>
                    </label>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Button 
              onClick={runRedTeamTest} 
              disabled={isRunning}
              className="w-full gap-2 bg-cyber-purple hover:bg-cyber-purple/80"
            >
              {isRunning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running Assessment...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Start Red Team Assessment
                </>
              )}
            </Button>

            {isRunning && (
              <div className="space-y-2">
                <Progress value={progress} className="h-2" />
                <p className="text-xs text-muted-foreground text-center">
                  Testing LLM vulnerabilities... {progress}%
                </p>
              </div>
            )}
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2 space-y-6">
            {summary && (
              <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Security Assessment Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
                    <div>
                      <div className={`text-4xl font-bold ${getGradeColor(summary.grade)}`}>
                        {summary.grade}
                      </div>
                      <p className="text-xs text-muted-foreground">Grade</p>
                    </div>
                    <div>
                      <div className="text-4xl font-bold text-cyber-cyan">{summary.securityScore}</div>
                      <p className="text-xs text-muted-foreground">Score /100</p>
                    </div>
                    <div>
                      <div className="text-4xl font-bold">{summary.totalTests}</div>
                      <p className="text-xs text-muted-foreground">Total Tests</p>
                    </div>
                    <div>
                      <div className="text-4xl font-bold text-red-500">{summary.criticalCount}</div>
                      <p className="text-xs text-muted-foreground">Critical</p>
                    </div>
                    <div>
                      <div className="text-4xl font-bold text-orange-500">{summary.highCount}</div>
                      <p className="text-xs text-muted-foreground">High</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {results.length > 0 && (
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {results.map((categoryResult, idx) => (
                    <Card key={idx} className="bg-card/50 backdrop-blur-sm border-border/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-lg flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-cyber-purple" />
                          {categoryResult.category}
                        </CardTitle>
                        <CardDescription>{categoryResult.description}</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {categoryResult.tests.map((test, testIdx) => (
                          <div 
                            key={testIdx} 
                            className={`p-3 rounded-lg border ${
                              test.vulnerable 
                                ? "border-red-500/30 bg-red-500/5" 
                                : "border-green-500/30 bg-green-500/5"
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2 mb-2">
                              <div className="flex items-center gap-2">
                                {test.vulnerable ? (
                                  <XCircle className="h-4 w-4 text-red-500" />
                                ) : (
                                  <CheckCircle className="h-4 w-4 text-green-500" />
                                )}
                                <span className="text-sm font-medium">
                                  {test.vulnerable ? "Vulnerable" : "Protected"}
                                </span>
                              </div>
                              {test.vulnerable && (
                                <Badge className={`${getSeverityColor(test.severity)} text-white`}>
                                  {test.severity.toUpperCase()}
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mb-2 font-mono">
                              Attack: {test.attack}...
                            </p>
                            <details className="text-xs">
                              <summary className="cursor-pointer text-cyber-cyan hover:underline">
                                View Response
                              </summary>
                              <pre className="mt-2 p-2 bg-background/50 rounded text-xs overflow-x-auto whitespace-pre-wrap">
                                {test.response}
                              </pre>
                            </details>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            )}

            {results.length === 0 && !isRunning && (
              <Card className="bg-card/50 backdrop-blur-sm border-dashed border-2">
                <CardContent className="flex flex-col items-center justify-center py-16">
                  <Brain className="h-16 w-16 text-muted-foreground/30 mb-4" />
                  <h3 className="text-lg font-semibold mb-2">No Results Yet</h3>
                  <p className="text-muted-foreground text-center max-w-md">
                    Configure your target system prompt, select vulnerability categories, 
                    and run the red team assessment to identify potential security weaknesses.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default LLMRedTeam;
