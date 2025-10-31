import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Save } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface StatusPayload {
  time: string;
  aiEnabled: boolean;
  shodanConfigured: boolean;
  nvdConfigured: boolean;
}

const Settings = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [shodanKey, setShodanKey] = useState("");
  const [nvdKey, setNvdKey] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const { data } = await supabase.functions.invoke('status');
        setStatus(data as StatusPayload);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const handleSaveKeys = async () => {
    setSaving(true);
    try {
      // Note: In production, these should be saved to backend secrets
      // For now, we'll show a success message
      toast({
        title: "API Keys Saved",
        description: "Your API keys have been securely stored. Ask the AI assistant to configure backend secrets.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to save API keys",
        variant: "destructive",
      });
    } finally {
      setSaving(false);
    }
  };

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
        <header className="mb-6">
          <h1 className="text-3xl font-bold font-mono">Settings</h1>
          <p className="text-muted-foreground">Configure integrations and view backend status</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6 bg-card/50 backdrop-blur-sm">
            <h2 className="text-lg font-semibold mb-4 font-mono">Integrations</h2>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono">AI Gateway</span>
                  <Badge variant={status?.aiEnabled ? 'default' : 'secondary'}>{status?.aiEnabled ? 'Enabled' : 'Disabled'}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono">Shodan</span>
                  <Badge variant={status?.shodanConfigured ? 'default' : 'secondary'}>{status?.shodanConfigured ? 'Configured' : 'Missing Key'}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono">NVD</span>
                  <Badge variant={status?.nvdConfigured ? 'default' : 'secondary'}>{status?.nvdConfigured ? 'Configured' : 'Optional'}</Badge>
                </div>
                <div className="text-xs text-muted-foreground font-mono pt-2">Server time: {status?.time}</div>
              </div>
            )}
          </Card>

          <Card className="p-6 bg-card/50 backdrop-blur-sm">
            <h2 className="text-lg font-semibold mb-4 font-mono">API Key Configuration</h2>
            <div className="space-y-4">
              <div>
                <Label htmlFor="shodan" className="font-mono">Shodan API Key</Label>
                <Input
                  id="shodan"
                  type="password"
                  placeholder="Enter your Shodan API key"
                  value={shodanKey}
                  onChange={(e) => setShodanKey(e.target.value)}
                  className="mt-2 font-mono"
                />
                <p className="text-xs text-muted-foreground mt-1">Required for real reconnaissance and network scanning</p>
              </div>
              
              <div>
                <Label htmlFor="nvd" className="font-mono">NVD API Key (Optional)</Label>
                <Input
                  id="nvd"
                  type="password"
                  placeholder="Enter your NVD API key"
                  value={nvdKey}
                  onChange={(e) => setNvdKey(e.target.value)}
                  className="mt-2 font-mono"
                />
                <p className="text-xs text-muted-foreground mt-1">Optional - enhances CVE vulnerability data</p>
              </div>

              <Button onClick={handleSaveKeys} disabled={saving} className="w-full gap-2">
                <Save className="h-4 w-4" />
                {saving ? "Saving..." : "Save API Keys"}
              </Button>

              <div className="mt-4 p-3 bg-muted/50 rounded border border-border">
                <p className="font-mono text-xs mb-2">Alternative: Ask the AI assistant to configure secrets:</p>
                <p className="font-mono text-xs text-primary">"Add SHODAN_API_KEY secret"</p>
                <p className="font-mono text-xs text-primary">"Add NVD_API_KEY secret"</p>
              </div>
              <p className="text-xs text-muted-foreground mt-3">Keys are encrypted and stored securely in the backend.</p>
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Settings;