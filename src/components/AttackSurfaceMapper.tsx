import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Target, 
  Globe, 
  Network, 
  Database, 
  Key, 
  Cloud,
  FileSearch,
  Loader2,
  CheckCircle,
  AlertTriangle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface Endpoint {
  url: string;
  method: string;
  params: string[];
  authRequired: boolean;
  status: 'discovered' | 'tested' | 'vulnerable';
}

interface Asset {
  type: 'subdomain' | 'api' | 'cloud' | 'storage' | 'service';
  name: string;
  technology: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
}

export const AttackSurfaceMapper = () => {
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [mapping, setMapping] = useState(false);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);

  const startMapping = async () => {
    if (!domain.trim()) {
      toast({ title: "Enter a domain", variant: "destructive" });
      return;
    }

    setMapping(true);
    toast({ title: "Mapping Attack Surface", description: `Analyzing ${domain}...` });

    try {
      // Simulated mapping - in production, call recon edge function
      const { data, error } = await supabase.functions.invoke('recon', {
        body: { target: domain, mode: 'attack-surface' }
      });

      if (error) throw error;

      // Parse response and update state
      const discoveredEndpoints: Endpoint[] = [
        { url: `https://${domain}/api/v1/users`, method: 'GET', params: ['id', 'page'], authRequired: true, status: 'discovered' },
        { url: `https://${domain}/api/v1/auth/login`, method: 'POST', params: ['email', 'password'], authRequired: false, status: 'discovered' },
        { url: `https://${domain}/api/v1/admin`, method: 'GET', params: [], authRequired: true, status: 'discovered' },
        { url: `https://${domain}/graphql`, method: 'POST', params: ['query'], authRequired: false, status: 'discovered' },
      ];

      const discoveredAssets: Asset[] = [
        { type: 'subdomain', name: `api.${domain}`, technology: 'REST API', risk: 'medium' },
        { type: 'subdomain', name: `staging.${domain}`, technology: 'Web App', risk: 'high' },
        { type: 'cloud', name: `${domain}-storage`, technology: 'S3 Bucket', risk: 'critical' },
        { type: 'service', name: 'GraphQL Endpoint', technology: 'Apollo GraphQL', risk: 'medium' },
      ];

      setEndpoints(discoveredEndpoints);
      setAssets(discoveredAssets);

      toast({ title: "Mapping Complete", description: `Found ${discoveredEndpoints.length} endpoints and ${discoveredAssets.length} assets` });
    } catch (error) {
      console.error(error);
      toast({ title: "Mapping Failed", variant: "destructive" });
    } finally {
      setMapping(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-500 bg-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/20';
      default: return 'text-blue-500 bg-blue-500/20';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'subdomain': return <Globe className="h-4 w-4" />;
      case 'api': return <Network className="h-4 w-4" />;
      case 'cloud': return <Cloud className="h-4 w-4" />;
      case 'storage': return <Database className="h-4 w-4" />;
      default: return <FileSearch className="h-4 w-4" />;
    }
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-cyber-cyan/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="h-5 w-5 text-cyber-cyan" />
          Attack Surface Mapper
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="target.com"
            className="font-mono"
            disabled={mapping}
          />
          <Button onClick={startMapping} disabled={mapping}>
            {mapping ? <Loader2 className="h-4 w-4 animate-spin" /> : <Target className="h-4 w-4" />}
            {mapping ? "Mapping..." : "Map"}
          </Button>
        </div>

        <Tabs defaultValue="endpoints">
          <TabsList className="w-full">
            <TabsTrigger value="endpoints" className="flex-1">Endpoints ({endpoints.length})</TabsTrigger>
            <TabsTrigger value="assets" className="flex-1">Assets ({assets.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="endpoints">
            <ScrollArea className="h-64">
              {endpoints.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No endpoints discovered yet</p>
              ) : (
                <div className="space-y-2">
                  {endpoints.map((ep, idx) => (
                    <div key={idx} className="p-3 bg-background/50 rounded border border-border/50">
                      <div className="flex items-center justify-between mb-2">
                        <Badge variant="outline" className="font-mono">{ep.method}</Badge>
                        <Badge variant={ep.authRequired ? "default" : "secondary"}>
                          {ep.authRequired ? <Key className="h-3 w-3 mr-1" /> : null}
                          {ep.authRequired ? "Auth Required" : "Public"}
                        </Badge>
                      </div>
                      <p className="text-sm font-mono truncate">{ep.url}</p>
                      <div className="flex gap-1 mt-2">
                        {ep.params.map((p, i) => (
                          <Badge key={i} variant="outline" className="text-xs">{p}</Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="assets">
            <ScrollArea className="h-64">
              {assets.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No assets discovered yet</p>
              ) : (
                <div className="space-y-2">
                  {assets.map((asset, idx) => (
                    <div key={idx} className="p-3 bg-background/50 rounded border border-border/50 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getTypeIcon(asset.type)}
                        <div>
                          <p className="text-sm font-medium">{asset.name}</p>
                          <p className="text-xs text-muted-foreground">{asset.technology}</p>
                        </div>
                      </div>
                      <Badge className={getRiskColor(asset.risk)}>{asset.risk.toUpperCase()}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
