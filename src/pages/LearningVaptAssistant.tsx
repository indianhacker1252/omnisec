import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { CommandHeader } from "@/components/CommandHeader";
import { 
  ArrowLeft, 
  Brain, 
  Send, 
  History, 
  Lightbulb, 
  Settings, 
  ThumbsUp, 
  ThumbsDown,
  AlertTriangle,
  Target,
  Code,
  Shield,
  Loader2,
  Activity,
  CheckCircle,
  XCircle,
  HelpCircle
} from "lucide-react";

interface TestAction {
  id?: string;
  target_url: string;
  method: string;
  injection_point?: string;
  payload_sent?: string;
  transformed_payload?: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_status?: number;
  response_headers?: Record<string, string>;
  response_body?: string;
  outcome_label?: string;
  test_type: string;
  notes?: string;
  created_at?: string;
}

interface Suggestion {
  explanation: string;
  strategies: Array<{
    name: string;
    description: string;
    rationale: string;
    payload_template: string;
  }>;
  ethical_reminder?: string;
}

interface Config {
  mode: "observe_only" | "assistive" | "auto_sandboxed";
  allowed_targets: string[];
  log_level: string;
}

const TEST_TYPES = [
  "XSS", "SQLi", "SSRF", "IDOR", "CSRF", "XXE", "LFI", "RFI", 
  "Command Injection", "Path Traversal", "Authentication Bypass", "Other"
];

const INJECTION_POINTS = [
  "query_parameter", "path_parameter", "header", "cookie", 
  "body_field", "json_field", "xml_field", "multipart_field"
];

const OUTCOME_LABELS = [
  { value: "no_effect", label: "No Effect", icon: XCircle, color: "text-muted-foreground" },
  { value: "potential_issue", label: "Potential Issue", icon: HelpCircle, color: "text-yellow-500" },
  { value: "confirmed_issue", label: "Confirmed Issue", icon: CheckCircle, color: "text-green-500" },
];

export default function LearningVaptAssistant() {
  const navigate = useNavigate();
  const { toast } = useToast();
  
  // State
  const [activeTab, setActiveTab] = useState("log");
  const [loading, setLoading] = useState(false);
  const [actions, setActions] = useState<TestAction[]>([]);
  const [suggestions, setSuggestions] = useState<Suggestion | null>(null);
  const [similarActions, setSimilarActions] = useState<TestAction[]>([]);
  const [config, setConfig] = useState<Config>({ mode: "observe_only", allowed_targets: [], log_level: "info" });
  const [stats, setStats] = useState<any>(null);
  
  // Form state
  const [formData, setFormData] = useState<TestAction>({
    target_url: "",
    method: "GET",
    test_type: "XSS",
    injection_point: "query_parameter",
    payload_sent: "",
    outcome_label: "no_effect",
    notes: "",
  });

  const FUNCTION_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/vapt-learning`;

  useEffect(() => {
    loadActions();
    loadConfig();
    loadStats();
  }, []);

  const getHeaders = async () => {
    const { data: { session } } = await supabase.auth.getSession();
    return {
      "Content-Type": "application/json",
      ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}),
    };
  };

  const loadActions = async () => {
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/actions?limit=50`, { headers });
      const data = await response.json();
      if (data.actions) setActions(data.actions);
    } catch (error) {
      console.error("Failed to load actions:", error);
    }
  };

  const loadConfig = async () => {
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/config`, { headers });
      const data = await response.json();
      if (data.config) setConfig(data.config);
    } catch (error) {
      console.error("Failed to load config:", error);
    }
  };

  const loadStats = async () => {
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/stats`, { headers });
      const data = await response.json();
      if (data.stats) setStats(data.stats);
    } catch (error) {
      console.error("Failed to load stats:", error);
    }
  };

  const logAction = async () => {
    if (!formData.target_url || !formData.test_type) {
      toast({ title: "Error", description: "Target URL and Test Type are required", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/log-action`, {
        method: "POST",
        headers,
        body: JSON.stringify(formData),
      });
      
      const data = await response.json();
      
      if (data.success) {
        toast({ title: "Action Logged", description: "Test action recorded successfully" });
        setFormData({ ...formData, payload_sent: "", notes: "" });
        loadActions();
        loadStats();
        
        // Auto-get suggestions in assistive mode
        if (config.mode === "assistive" && data.action?.id) {
          await getSuggestions(data.action.id);
        }
      } else {
        toast({ title: "Error", description: data.error || "Failed to log action", variant: "destructive" });
      }
    } catch (error) {
      toast({ title: "Error", description: "Failed to log action", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const getSuggestions = async (actionId?: string) => {
    setLoading(true);
    setSuggestions(null);
    
    try {
      const headers = await getHeaders();
      const body = actionId 
        ? { action_id: actionId }
        : { current_action: formData };
      
      const response = await fetch(`${FUNCTION_URL}/suggestions`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      
      const data = await response.json();
      
      if (data.suggestions) {
        setSuggestions(data.suggestions);
        setActiveTab("suggestions");
        toast({ title: "Suggestions Ready", description: `Analyzed ${data.similar_actions_used} similar past actions` });
      } else {
        toast({ title: "Error", description: data.error || "Failed to get suggestions", variant: "destructive" });
      }
    } catch (error) {
      toast({ title: "Error", description: "Failed to get suggestions", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const findSimilar = async () => {
    setLoading(true);
    setSimilarActions([]);
    
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/similar`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          test_type: formData.test_type,
          injection_point: formData.injection_point,
          limit: 10,
        }),
      });
      
      const data = await response.json();
      
      if (data.similar_actions) {
        setSimilarActions(data.similar_actions);
        setActiveTab("history");
        toast({ title: "Found Similar Actions", description: `${data.similar_actions.length} similar actions found` });
      }
    } catch (error) {
      toast({ title: "Error", description: "Failed to find similar actions", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const submitFeedback = async (actionId: string, suggestionId: string | undefined, rating: string) => {
    try {
      const headers = await getHeaders();
      await fetch(`${FUNCTION_URL}/feedback`, {
        method: "POST",
        headers,
        body: JSON.stringify({ action_id: actionId, suggestion_id: suggestionId, rating }),
      });
      toast({ title: "Feedback Recorded", description: "Thank you for your feedback!" });
      loadStats();
    } catch (error) {
      toast({ title: "Error", description: "Failed to record feedback", variant: "destructive" });
    }
  };

  const saveConfig = async () => {
    try {
      const headers = await getHeaders();
      const response = await fetch(`${FUNCTION_URL}/config`, {
        method: "POST",
        headers,
        body: JSON.stringify(config),
      });
      
      const data = await response.json();
      if (data.success) {
        toast({ title: "Config Saved", description: "Assistant configuration updated" });
      }
    } catch (error) {
      toast({ title: "Error", description: "Failed to save config", variant: "destructive" });
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <CommandHeader />
      
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Button variant="outline" size="icon" onClick={() => navigate("/dashboard")} className="border-cyber-purple/30">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex-1">
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Brain className="h-8 w-8 text-cyber-purple" />
              Learning VAPT Assistant
            </h1>
            <p className="text-muted-foreground">AI-powered learning from your penetration testing activities</p>
          </div>
          <Badge variant={config.mode === "observe_only" ? "secondary" : config.mode === "assistive" ? "default" : "destructive"}>
            Mode: {config.mode.replace("_", " ")}
          </Badge>
        </div>

        {/* Ethical Warning */}
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0" />
            <p className="text-sm text-yellow-500">
              <strong>Authorized Testing Only:</strong> This tool is for authorized penetration testing only. 
              Ensure you have written permission before testing any target. Misuse is prohibited and may violate laws.
            </p>
          </CardContent>
        </Card>

        {/* Stats Overview */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="border-cyber-purple/30">
              <CardContent className="p-4 text-center">
                <Activity className="h-6 w-6 mx-auto mb-2 text-cyber-purple" />
                <div className="text-2xl font-bold">{stats.total_actions}</div>
                <div className="text-xs text-muted-foreground">Total Actions</div>
              </CardContent>
            </Card>
            <Card className="border-green-500/30">
              <CardContent className="p-4 text-center">
                <CheckCircle className="h-6 w-6 mx-auto mb-2 text-green-500" />
                <div className="text-2xl font-bold">{stats.by_outcome?.confirmed_issue || 0}</div>
                <div className="text-xs text-muted-foreground">Confirmed Issues</div>
              </CardContent>
            </Card>
            <Card className="border-yellow-500/30">
              <CardContent className="p-4 text-center">
                <HelpCircle className="h-6 w-6 mx-auto mb-2 text-yellow-500" />
                <div className="text-2xl font-bold">{stats.by_outcome?.potential_issue || 0}</div>
                <div className="text-xs text-muted-foreground">Potential Issues</div>
              </CardContent>
            </Card>
            <Card className="border-cyber-cyan/30">
              <CardContent className="p-4 text-center">
                <ThumbsUp className="h-6 w-6 mx-auto mb-2 text-cyber-cyan" />
                <div className="text-2xl font-bold">{stats.feedback_summary?.helpful || 0}</div>
                <div className="text-xs text-muted-foreground">Helpful Suggestions</div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid grid-cols-4 w-full max-w-xl">
            <TabsTrigger value="log" className="flex items-center gap-2">
              <Target className="h-4 w-4" /> Log Action
            </TabsTrigger>
            <TabsTrigger value="suggestions" className="flex items-center gap-2">
              <Lightbulb className="h-4 w-4" /> Suggestions
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center gap-2">
              <History className="h-4 w-4" /> History
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" /> Settings
            </TabsTrigger>
          </TabsList>

          {/* Log Action Tab */}
          <TabsContent value="log" className="space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <Card className="border-cyber-purple/30">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" /> Test Action Details
                  </CardTitle>
                  <CardDescription>Log your VAPT activity for learning and analysis</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="col-span-2">
                      <Label>Target URL *</Label>
                      <Input
                        placeholder="https://example.com/api/endpoint"
                        value={formData.target_url}
                        onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
                      />
                    </div>
                    
                    <div>
                      <Label>Method</Label>
                      <Select value={formData.method} onValueChange={(v) => setFormData({ ...formData, method: v })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"].map((m) => (
                            <SelectItem key={m} value={m}>{m}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div>
                      <Label>Test Type *</Label>
                      <Select value={formData.test_type} onValueChange={(v) => setFormData({ ...formData, test_type: v })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {TEST_TYPES.map((t) => (
                            <SelectItem key={t} value={t}>{t}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div>
                      <Label>Injection Point</Label>
                      <Select value={formData.injection_point} onValueChange={(v) => setFormData({ ...formData, injection_point: v })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {INJECTION_POINTS.map((p) => (
                            <SelectItem key={p} value={p}>{p.replace("_", " ")}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div>
                      <Label>Outcome</Label>
                      <Select value={formData.outcome_label} onValueChange={(v) => setFormData({ ...formData, outcome_label: v })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {OUTCOME_LABELS.map((o) => (
                            <SelectItem key={o.value} value={o.value}>
                              <span className={o.color}>{o.label}</span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="col-span-2">
                      <Label>Payload Sent</Label>
                      <Textarea
                        placeholder="<script>alert(1)</script> or {{PAYLOAD}}"
                        value={formData.payload_sent}
                        onChange={(e) => setFormData({ ...formData, payload_sent: e.target.value })}
                        className="font-mono text-sm"
                        rows={3}
                      />
                    </div>
                    
                    <div className="col-span-2">
                      <Label>Notes</Label>
                      <Textarea
                        placeholder="Additional observations, WAF behavior, response patterns..."
                        value={formData.notes}
                        onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                        rows={2}
                      />
                    </div>
                  </div>
                  
                  <div className="flex gap-2 pt-4">
                    <Button onClick={logAction} disabled={loading} className="flex-1">
                      {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Send className="h-4 w-4 mr-2" />}
                      Log Action
                    </Button>
                    <Button variant="outline" onClick={() => getSuggestions()} disabled={loading}>
                      <Lightbulb className="h-4 w-4 mr-2" />
                      Get Suggestions
                    </Button>
                    <Button variant="outline" onClick={findSimilar} disabled={loading}>
                      <History className="h-4 w-4 mr-2" />
                      Find Similar
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Quick Actions */}
              <Card className="border-cyber-purple/30">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Code className="h-5 w-5" /> Recent Actions
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px]">
                    {actions.length === 0 ? (
                      <p className="text-muted-foreground text-center py-8">No actions logged yet</p>
                    ) : (
                      <div className="space-y-3">
                        {actions.slice(0, 10).map((action) => (
                          <div key={action.id} className="p-3 rounded border border-border/50 hover:border-cyber-purple/50 transition-colors">
                            <div className="flex items-center justify-between mb-1">
                              <Badge variant="outline">{action.test_type}</Badge>
                              <Badge variant={
                                action.outcome_label === "confirmed_issue" ? "default" :
                                action.outcome_label === "potential_issue" ? "secondary" : "outline"
                              }>
                                {action.outcome_label}
                              </Badge>
                            </div>
                            <p className="text-sm font-mono truncate">{action.target_url}</p>
                            <p className="text-xs text-muted-foreground">
                              {action.method} • {action.injection_point} • {new Date(action.created_at!).toLocaleString()}
                            </p>
                            <div className="flex gap-2 mt-2">
                              <Button size="sm" variant="ghost" onClick={() => getSuggestions(action.id)}>
                                <Lightbulb className="h-3 w-3 mr-1" /> Suggest
                              </Button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Suggestions Tab */}
          <TabsContent value="suggestions">
            <Card className="border-cyber-purple/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lightbulb className="h-5 w-5 text-yellow-500" /> AI-Powered Improvement Suggestions
                </CardTitle>
                <CardDescription>Based on your test and similar past actions</CardDescription>
              </CardHeader>
              <CardContent>
                {!suggestions ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Lightbulb className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Log an action and click "Get Suggestions" to receive AI-powered improvement recommendations</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {/* Explanation */}
                    <div className="p-4 rounded-lg bg-muted/50">
                      <h4 className="font-semibold mb-2">Analysis</h4>
                      <p className="text-sm">{suggestions.explanation}</p>
                    </div>
                    
                    {/* Strategies */}
                    <div className="space-y-4">
                      <h4 className="font-semibold">Suggested Strategies</h4>
                      {suggestions.strategies?.map((strategy, i) => (
                        <Card key={i} className="border-cyber-cyan/30">
                          <CardContent className="p-4 space-y-3">
                            <div className="flex items-center justify-between">
                              <h5 className="font-medium text-cyber-cyan">{strategy.name}</h5>
                              <div className="flex gap-1">
                                <Button size="sm" variant="ghost" onClick={() => submitFeedback("", "", "helpful")}>
                                  <ThumbsUp className="h-3 w-3" />
                                </Button>
                                <Button size="sm" variant="ghost" onClick={() => submitFeedback("", "", "not_helpful")}>
                                  <ThumbsDown className="h-3 w-3" />
                                </Button>
                              </div>
                            </div>
                            <p className="text-sm">{strategy.description}</p>
                            <p className="text-sm text-muted-foreground"><strong>Rationale:</strong> {strategy.rationale}</p>
                            {strategy.payload_template && (
                              <div className="p-2 rounded bg-background font-mono text-xs overflow-x-auto">
                                {strategy.payload_template}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                    
                    {/* Ethical Reminder */}
                    {suggestions.ethical_reminder && (
                      <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/30 flex items-start gap-3">
                        <Shield className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                        <p className="text-sm text-yellow-500">{suggestions.ethical_reminder}</p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history">
            <Card className="border-cyber-purple/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="h-5 w-5" /> Test Action History
                </CardTitle>
                <CardDescription>
                  {similarActions.length > 0 
                    ? `Showing ${similarActions.length} similar actions`
                    : `Showing last ${actions.length} actions`
                  }
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <div className="space-y-3">
                    {(similarActions.length > 0 ? similarActions : actions).map((action) => (
                      <Card key={action.id} className="border-border/50">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Badge>{action.test_type}</Badge>
                              <Badge variant="outline">{action.method}</Badge>
                              {action.injection_point && <Badge variant="secondary">{action.injection_point}</Badge>}
                            </div>
                            <Badge variant={
                              action.outcome_label === "confirmed_issue" ? "default" :
                              action.outcome_label === "potential_issue" ? "secondary" : "outline"
                            }>
                              {action.outcome_label}
                            </Badge>
                          </div>
                          <p className="font-mono text-sm truncate mb-1">{action.target_url}</p>
                          {action.payload_sent && (
                            <p className="text-xs font-mono bg-muted p-2 rounded truncate mb-2">{action.payload_sent}</p>
                          )}
                          {action.notes && <p className="text-sm text-muted-foreground">{action.notes}</p>}
                          <p className="text-xs text-muted-foreground mt-2">
                            {new Date(action.created_at!).toLocaleString()}
                          </p>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings">
            <Card className="border-cyber-purple/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" /> Assistant Configuration
                </CardTitle>
                <CardDescription>Configure the learning assistant behavior</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div>
                    <Label>Operation Mode</Label>
                    <Select value={config.mode} onValueChange={(v: Config["mode"]) => setConfig({ ...config, mode: v })}>
                      <SelectTrigger className="mt-2">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="observe_only">
                          <div className="flex flex-col">
                            <span>Observe Only</span>
                            <span className="text-xs text-muted-foreground">Only logs data, suggests when asked</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="assistive">
                          <div className="flex flex-col">
                            <span>Assistive</span>
                            <span className="text-xs text-muted-foreground">Auto-suggests after each action</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="auto_sandboxed">
                          <div className="flex flex-col">
                            <span>Auto-Sandboxed</span>
                            <span className="text-xs text-muted-foreground">Can auto-execute in sandbox (requires setup)</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <Label>Allowed Targets (whitelist)</Label>
                    <Textarea
                      className="mt-2 font-mono"
                      placeholder="example.com&#10;192.168.1.0/24&#10;*.test.local"
                      value={config.allowed_targets?.join("\n") || ""}
                      onChange={(e) => setConfig({ 
                        ...config, 
                        allowed_targets: e.target.value.split("\n").filter(Boolean) 
                      })}
                      rows={4}
                    />
                    <p className="text-xs text-muted-foreground mt-1">One target per line. Supports wildcards.</p>
                  </div>
                  
                  <div>
                    <Label>Log Level</Label>
                    <Select value={config.log_level} onValueChange={(v) => setConfig({ ...config, log_level: v })}>
                      <SelectTrigger className="mt-2">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="debug">Debug</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                        <SelectItem value="warn">Warning</SelectItem>
                        <SelectItem value="error">Error</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                
                <Button onClick={saveConfig} className="w-full">
                  Save Configuration
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
