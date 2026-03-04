import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Activity, Search, Globe } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { enumerateAndQueue, type EnumerationResult } from "@/services/ReconOrchestrator";
import { normalizeFinding } from "@/services/DataNormalizer";
import { useScanHistory } from "@/hooks/useScanHistory";

export const ReconScanPanel = ({ onScanComplete }: { onScanComplete?: () => void }) => {
  const { toast } = useToast();
  const { logScan, completeScan, createAlert } = useScanHistory();
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [lastResult, setLastResult] = useState<EnumerationResult | null>(null);

  const startScan = async () => {
    if (!target.trim()) {
      toast({ title: "Invalid Target", description: "Enter a valid domain", variant: "destructive" });
      return;
    }

    setScanning(true);
    toast({ title: "Recon Started", description: `Enumerating subdomains for ${target}` });

    const scanId = await logScan({ module: "recon", scanType: "Recursive Reconnaissance", target });

    try {
      const result = await enumerateAndQueue(target);
      setLastResult(result);

      // Normalize each subdomain as a finding
      for (const sub of result.subdomains) {
        await normalizeFinding({
          target_host: sub.subdomain,
          finding_type: "subdomain_discovered",
          title: `Subdomain: ${sub.subdomain}`,
          description: `Resolved to ${sub.ip}`,
          severity: "info",
          source_module: "recon",
          raw_data: sub,
        });
      }

      if (scanId) {
        await completeScan(scanId, {
          status: "completed",
          findingsCount: result.total,
          report: { domain: result.domain, subdomains: result.subdomains },
        });
      }

      // Alert if many subdomains found
      if (result.total > 20) {
        await createAlert({
          type: "large_attack_surface",
          severity: "medium",
          title: `Large Attack Surface: ${result.domain}`,
          description: `Discovered ${result.total} live subdomains`,
          sourceModule: "recon",
          target: target,
        });
      }

      toast({ title: "Recon Complete", description: `Found ${result.total} live subdomains, all queued for scanning` });
      onScanComplete?.();
    } catch (e) {
      console.error(e);
      if (scanId) await completeScan(scanId, { status: "failed" });
      toast({ title: "Scan Failed", description: e instanceof Error ? e.message : "Unknown error", variant: "destructive" });
    } finally {
      setScanning(false);
    }
  };

  return (
    <Card className="p-6 bg-card/50 backdrop-blur-sm">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Activity className="h-5 w-5 text-primary" />
        Recursive Recon Pipeline
      </h3>

      <div className="space-y-4">
        <div>
          <label className="text-sm font-mono mb-2 block">Target Domain</label>
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
            className="font-mono bg-background/50"
            disabled={scanning}
          />
        </div>

        <Button onClick={startScan} disabled={scanning} className="w-full bg-primary hover:bg-primary/80 text-primary-foreground">
          {scanning ? (
            <>
              <Activity className="h-4 w-4 mr-2 animate-spin" />
              Enumerating & Queuing...
            </>
          ) : (
            <>
              <Search className="h-4 w-4 mr-2" />
              Start Recursive Recon
            </>
          )}
        </Button>

        {lastResult && (
          <div className="pt-4 border-t border-border/50 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground font-mono">Domain</span>
              <span className="font-mono">{lastResult.domain}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground font-mono">Live Subdomains</span>
              <Badge variant="secondary">{lastResult.total}</Badge>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground font-mono">Queued</span>
              <Badge variant="secondary">{lastResult.queuedForScanning}</Badge>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground font-mono">Pipeline</span>
              <Badge variant="secondary">Subdomain → DNS → Queue</Badge>
            </div>
          </div>
        )}

        <div className="pt-4 border-t border-border/50 space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground font-mono">MITRE</span>
            <Badge variant="secondary">T1046 / T1595</Badge>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground font-mono">Dedup</span>
            <Badge variant="secondary">Hash-based</Badge>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground font-mono">Verification</span>
            <Badge variant="secondary">Dual-probe</Badge>
          </div>
        </div>
      </div>
    </Card>
  );
};
