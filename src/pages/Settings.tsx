import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

interface StatusPayload {
  time: string;
  aiEnabled: boolean;
  shodanConfigured: boolean;
  nvdConfigured: boolean;
}

const Settings = () => {
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
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
            <h2 className="text-lg font-semibold mb-4 font-mono">How to Add API Keys</h2>
            <div className="space-y-3 text-sm text-muted-foreground">
              <p>API keys are required for certain features:</p>
              <ul className="list-disc pl-5 space-y-2">
                <li><strong>Shodan API Key</strong>: Required for real reconnaissance data</li>
                <li><strong>NVD API Key</strong>: Optional for enhanced CVE vulnerability data</li>
                <li><strong>AI Gateway</strong>: Pre-configured, no key needed</li>
              </ul>
              <div className="mt-4 p-3 bg-muted/50 rounded border border-border">
                <p className="font-mono text-xs">To add API keys, ask the AI assistant in chat:</p>
                <p className="font-mono text-xs mt-2 text-primary">"Add SHODAN_API_KEY secret"</p>
                <p className="font-mono text-xs text-primary">"Add NVD_API_KEY secret"</p>
              </div>
              <p className="text-xs mt-3">Keys are encrypted and stored securely in the backend, never exposed to the browser.</p>
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Settings;