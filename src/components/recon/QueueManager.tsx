import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Layers, RefreshCw, Trash2 } from "lucide-react";
import { getQueueStatus, getQueueItems, clearQueue, type QueueStatus } from "@/services/ReconOrchestrator";
import { supabase } from "@/integrations/supabase/client";

export const QueueManager = ({ domain }: { domain?: string }) => {
  const [status, setStatus] = useState<QueueStatus>({ pending: 0, scanning: 0, completed: 0, failed: 0, total: 0 });
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const [s, q] = await Promise.all([getQueueStatus(), getQueueItems(domain)]);
      setStatus(s);
      setItems(q);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // Subscribe to realtime updates
    const channel = supabase
      .channel("recon-queue-changes")
      .on("postgres_changes", { event: "*", schema: "public", table: "recon_queue" }, () => {
        refresh();
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [domain]);

  const completionPct = status.total > 0
    ? Math.round(((status.completed + status.failed) / status.total) * 100)
    : 0;

  return (
    <Card className="p-5 bg-card/50 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Layers className="h-5 w-5 text-primary" />
          Recon Queue
        </h3>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => clearQueue(domain).then(refresh)}>
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        {([
          ["Pending", status.pending, "bg-yellow-500/20 text-yellow-400"],
          ["Scanning", status.scanning, "bg-blue-500/20 text-blue-400"],
          ["Done", status.completed, "bg-green-500/20 text-green-400"],
          ["Failed", status.failed, "bg-red-500/20 text-red-400"],
        ] as const).map(([label, count, cls]) => (
          <div key={label} className={`rounded-lg p-3 text-center ${cls}`}>
            <div className="text-2xl font-bold font-mono">{count}</div>
            <div className="text-xs opacity-80">{label}</div>
          </div>
        ))}
      </div>

      <Progress value={completionPct} className="mb-4" />
      <p className="text-xs text-muted-foreground mb-3">{completionPct}% processed • {status.total} total subdomains</p>

      <ScrollArea className="h-48">
        <div className="space-y-1">
          {items.slice(0, 50).map((item) => (
            <div key={item.id} className="flex items-center justify-between p-2 bg-background/50 rounded text-sm font-mono">
              <span className="truncate flex-1">{item.subdomain}</span>
              <div className="flex items-center gap-2 ml-2">
                {item.ip_address && <span className="text-xs text-muted-foreground">{item.ip_address}</span>}
                <Badge variant={
                  item.status === "completed" ? "default" :
                  item.status === "failed" ? "destructive" :
                  item.status === "scanning" ? "secondary" : "outline"
                } className="text-xs">
                  {item.status}
                </Badge>
              </div>
            </div>
          ))}
          {items.length === 0 && <p className="text-center text-muted-foreground text-sm py-4">Queue empty</p>}
        </div>
      </ScrollArea>
    </Card>
  );
};
