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
            <h2 className="text-lg font-semibold mb-4 font-mono">Requirements</h2>
            <ul className="list-disc pl-5 space-y-2 text-sm text-muted-foreground">
              <li>To enable real Recon data, provide a Shodan API key.</li>
              <li>For richer CVE results, optionally add an NVD API key.</li>
              <li>AI chat uses the built-in Lovable AI gateway—no key needed.</li>
              <li>Keys are stored securely in the backend and never exposed to the browser.</li>
            </ul>
            <p className="text-xs text-muted-foreground mt-3">Add or update keys via the assistant in this chat—I'll prompt you when needed.</p>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Settings;