import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, CheckCircle2, XCircle, Key, Save, Eye, EyeOff } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface StatusPayload {
  time: string;
  aiEnabled: boolean;
  shodanConfigured: boolean;
  nvdConfigured: boolean;
}

interface ApiKeyConfig {
  key: string;
  label: string;
  description: string;
  placeholder: string;
  required: boolean;
}

const API_KEYS: ApiKeyConfig[] = [
  {
    key: "SHODAN_API_KEY",
    label: "Shodan API Key",
    description: "Required for reconnaissance and network scanning",
    placeholder: "Enter your Shodan API key",
    required: true,
  },
  {
    key: "NVD_API_KEY",
    label: "NVD API Key",
    description: "Optional - Improves vulnerability intelligence rate limits",
    placeholder: "Enter your NVD API key",
    required: false,
  },
  {
    key: "OPENAI_API_KEY",
    label: "OpenAI API Key",
    description: "Optional - For Voice Assistant (alternative to Lovable AI)",
    placeholder: "Enter your OpenAI API key",
    required: false,
  },
];

const Settings = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState<Record<string, boolean>>({});

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

  const handleSaveKey = async (keyName: string) => {
    const value = apiKeys[keyName];
    if (!value?.trim()) {
      toast({
        title: "Error",
        description: "Please enter a valid API key",
        variant: "destructive",
      });
      return;
    }

    setSaving(prev => ({ ...prev, [keyName]: true }));
    
    try {
      // Store the key in the backend via edge function
      const { error } = await supabase.functions.invoke('status', {
        body: { action: 'save-key', keyName, keyValue: value.trim() }
      });
      
      if (error) throw error;
      
      toast({
        title: "API Key Saved",
        description: `${keyName} has been securely stored`,
      });
      
      // Clear the input after saving
      setApiKeys(prev => ({ ...prev, [keyName]: '' }));
      
      // Refresh status
      const { data } = await supabase.functions.invoke('status');
      if (data) setStatus(data as StatusPayload);
      
    } catch (err: any) {
      console.error("Error saving key:", err);
      toast({
        title: "Save Failed",
        description: "API keys can only be configured through the Lovable secrets management. Please use the 'Add API Key' button below.",
        variant: "destructive",
      });
    } finally {
      setSaving(prev => ({ ...prev, [keyName]: false }));
    }
  };

  const toggleShowKey = (keyName: string) => {
    setShowKeys(prev => ({ ...prev, [keyName]: !prev[keyName] }));
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
          <p className="text-muted-foreground">Manage API keys and system integrations</p>
        </header>

        <div className="grid gap-6 max-w-3xl">
          {/* Integration Status */}
          <Card className="p-6 bg-card/50 backdrop-blur-sm">
            <h2 className="text-lg font-semibold mb-4 font-mono">Integration Status</h2>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading status...</p>
            ) : status ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-background/50 rounded-lg">
                  <span className="font-mono">Lovable AI Gateway</span>
                  {status.aiEnabled ? (
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Enabled (No API Key Required)
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

          {/* AI Assistant Info */}
          <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-cyan/30">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-cyber-cyan/20 rounded-lg">
                <CheckCircle2 className="h-5 w-5 text-cyber-cyan" />
              </div>
              <div>
                <h2 className="text-lg font-semibold font-mono">AI Assistant</h2>
                <p className="text-sm text-muted-foreground">Powered by Lovable AI</p>
              </div>
            </div>
            <div className="p-4 bg-cyber-cyan/5 rounded-lg border border-cyber-cyan/20">
              <p className="text-sm text-foreground">
                The AI Assistant uses <strong>Lovable AI Gateway</strong> which is pre-configured and requires no additional API keys. 
                It provides access to advanced AI models for security analysis, threat intelligence, and penetration testing guidance.
              </p>
              <ul className="mt-3 text-sm text-muted-foreground space-y-1">
                <li>• Google Gemini 2.5 Flash (default)</li>
                <li>• OpenAI GPT-5 (available)</li>
                <li>• Streaming responses with real-time output</li>
              </ul>
            </div>
          </Card>

          {/* API Key Configuration */}
          <Card className="p-6 bg-card/50 backdrop-blur-sm">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-cyber-purple/20 rounded-lg">
                <Key className="h-5 w-5 text-cyber-purple" />
              </div>
              <div>
                <h2 className="text-lg font-semibold font-mono">API Key Configuration</h2>
                <p className="text-sm text-muted-foreground">Configure optional integrations</p>
              </div>
            </div>

            <div className="space-y-6">
              {API_KEYS.map((config) => (
                <div key={config.key} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor={config.key} className="font-mono text-sm">
                      {config.label}
                      {config.required && <span className="text-red-400 ml-1">*</span>}
                    </Label>
                    {!config.required && (
                      <Badge variant="outline" className="text-xs">Optional</Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">{config.description}</p>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <Input
                        id={config.key}
                        type={showKeys[config.key] ? "text" : "password"}
                        value={apiKeys[config.key] || ''}
                        onChange={(e) => setApiKeys(prev => ({ ...prev, [config.key]: e.target.value }))}
                        placeholder={config.placeholder}
                        className="font-mono text-sm pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => toggleShowKey(config.key)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        {showKeys[config.key] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                    <Button
                      onClick={() => handleSaveKey(config.key)}
                      disabled={saving[config.key] || !apiKeys[config.key]?.trim()}
                      className="gap-2"
                    >
                      <Save className="h-4 w-4" />
                      {saving[config.key] ? "Saving..." : "Save"}
                    </Button>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 p-4 bg-amber-500/10 rounded-lg border border-amber-500/20">
              <p className="text-sm text-amber-400 font-medium mb-2">⚠️ Important Security Notice</p>
              <p className="text-xs text-amber-500/80">
                API keys are stored securely in the backend secrets system. For production use, 
                configure keys through your Lovable project's Secrets management panel. 
                Never store API keys in client-side code.
              </p>
            </div>
          </Card>

          {/* Get API Keys */}
          <Card className="p-6 bg-card/50 backdrop-blur-sm">
            <h2 className="text-lg font-semibold mb-4 font-mono">How to Get API Keys</h2>
            <div className="space-y-4 text-sm">
              <div className="p-3 bg-background/50 rounded-lg">
                <p className="font-mono text-cyber-cyan mb-1">Shodan API Key</p>
                <p className="text-muted-foreground text-xs">
                  Sign up at <a href="https://shodan.io" target="_blank" rel="noopener noreferrer" className="text-cyber-cyan hover:underline">shodan.io</a> → 
                  Go to Account → API Key
                </p>
              </div>
              <div className="p-3 bg-background/50 rounded-lg">
                <p className="font-mono text-cyber-cyan mb-1">NVD API Key</p>
                <p className="text-muted-foreground text-xs">
                  Request at <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-cyber-cyan hover:underline">nvd.nist.gov</a> → 
                  Increases rate limits for vulnerability queries
                </p>
              </div>
              <div className="p-3 bg-background/50 rounded-lg">
                <p className="font-mono text-cyber-cyan mb-1">OpenAI API Key</p>
                <p className="text-muted-foreground text-xs">
                  Get from <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" className="text-cyber-cyan hover:underline">platform.openai.com</a> → 
                  Only needed if you want Voice Assistant with OpenAI (Lovable AI works without this)
                </p>
              </div>
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Settings;