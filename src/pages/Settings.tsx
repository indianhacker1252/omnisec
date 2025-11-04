import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, CheckCircle2, XCircle } from "lucide-react";
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

  useEffect(() => {
    (async () => {
      try {
        const { data, error } = await supabase.functions.invoke('status');
        if (error) {
          if (error.message?.includes("403")) {
            toast({
              title: "Admin Access Required",
              description: "You need admin privileges to view detailed status",
              variant: "destructive",
            });
          }
        } else {
          setStatus(data as StatusPayload);
        }
      } catch (err) {
        console.error("Error fetching status:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, [toast]);

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
          <p className="text-muted-foreground">View system integration status</p>
        </header>

        <Card className="p-6 bg-card/50 backdrop-blur-sm max-w-2xl">
          <h2 className="text-lg font-semibold mb-4 font-mono">Integration Status</h2>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading status...</p>
          ) : status ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-background/50 rounded-lg">
                <span className="font-mono">AI Gateway</span>
                {status.aiEnabled ? (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    Enabled
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Disabled
                  </Badge>
                )}
              </div>

              <div className="flex items-center justify-between p-3 bg-background/50 rounded-lg">
                <span className="font-mono">Shodan Integration</span>
                {status.shodanConfigured ? (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    Configured
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Not Configured
                  </Badge>
                )}
              </div>

              <div className="flex items-center justify-between p-3 bg-background/50 rounded-lg">
                <span className="font-mono">NVD Integration</span>
                {status.nvdConfigured ? (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    Configured
                  </Badge>
                ) : (
                  <Badge variant="secondary">Optional</Badge>
                )}
              </div>

              <div className="text-xs text-muted-foreground font-mono pt-2">
                Server time: {status.time}
              </div>
            </div>
          ) : (
            <div className="p-4 bg-muted/50 rounded border border-border">
              <p className="text-sm text-muted-foreground">
                Unable to fetch status. You may not have admin permissions.
              </p>
            </div>
          )}
        </Card>

        <Card className="p-6 bg-card/50 backdrop-blur-sm mt-6 max-w-2xl">
          <h2 className="text-lg font-semibold mb-4 font-mono">API Key Configuration</h2>
          <div className="space-y-4 text-sm text-muted-foreground">
            <p>
              API keys are managed securely through the backend secrets system. 
              Contact your administrator or use the AI assistant to configure:
            </p>
            <ul className="list-disc list-inside space-y-2 ml-4">
              <li>
                <code className="text-primary font-mono">SHODAN_API_KEY</code> - For reconnaissance scanning
              </li>
              <li>
                <code className="text-primary font-mono">NVD_API_KEY</code> - For vulnerability intelligence (optional)
              </li>
            </ul>
            <div className="mt-4 p-3 bg-amber-500/10 rounded border border-amber-500/20">
              <p className="text-xs text-amber-500">
                ⚠️ Security Notice: Never store API keys in client-side code or configuration files.
                Always use secure backend secrets management.
              </p>
            </div>
          </div>
        </Card>
      </main>
    </div>
  );
};

export default Settings;
