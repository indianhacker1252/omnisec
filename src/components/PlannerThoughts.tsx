// OmniSec™ © HARSH MALIK
// PlannerThoughts — live stream of AI planner decisions + queued detector jobs.

import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Brain, Cpu, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

interface Props { scanId?: string | null }

interface Decision {
  id: string; step: number; decision: string; rationale: string | null;
  tool_call: any; tool_result: any; created_at: string;
}
interface Job {
  id: string; detector: string; status: string; error: string | null; updated_at: string;
}

export function PlannerThoughts({ scanId }: Props) {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    const load = async () => {
      const [d, j] = await Promise.all([
        supabase.from("planner_decisions").select("*").eq("scan_id", scanId).order("created_at", { ascending: true }).limit(200),
        supabase.from("scan_jobs").select("id,detector,status,error,updated_at").eq("scan_id", scanId).order("updated_at", { ascending: false }).limit(100),
      ]);
      if (cancelled) return;
      if (d.data) setDecisions(d.data as Decision[]);
      if (j.data) setJobs(j.data as Job[]);
    };
    load();

    const ch = supabase.channel(`planner-${scanId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "planner_decisions", filter: `scan_id=eq.${scanId}` }, load)
      .on("postgres_changes", { event: "*", schema: "public", table: "scan_jobs", filter: `scan_id=eq.${scanId}` }, load)
      .subscribe();

    return () => { cancelled = true; supabase.removeChannel(ch); };
  }, [scanId]);

  const stats = useMemo(() => {
    const s = { pending: 0, running: 0, completed: 0, failed: 0 };
    for (const j of jobs) (s as any)[j.status] = ((s as any)[j.status] ?? 0) + 1;
    return s;
  }, [jobs]);

  if (!scanId) {
    return (
      <Card className="p-6 border-cyber-purple/30">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Brain className="w-5 h-5" /> Start a scan to see live planner decisions.
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-4 border-cyber-purple/30 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold flex items-center gap-2"><Brain className="w-5 h-5 text-primary" />Planner Thoughts</h3>
        <div className="flex gap-2 text-xs">
          <Badge variant="outline">pending {stats.pending}</Badge>
          <Badge variant="secondary">running {stats.running}</Badge>
          <Badge>completed {stats.completed}</Badge>
          {stats.failed > 0 && <Badge variant="destructive">failed {stats.failed}</Badge>}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <ScrollArea className="h-[320px] pr-3">
          <div className="space-y-2">
            {decisions.length === 0 && (
              <div className="text-xs text-muted-foreground">Awaiting planner...</div>
            )}
            {decisions.map(d => (
              <div key={d.id} className="text-xs border border-border/50 rounded p-2 bg-background/40">
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant="outline" className="text-[10px]">step {d.step}</Badge>
                  <span className="font-mono font-semibold text-primary">{d.decision}</span>
                </div>
                {d.rationale && <p className="text-muted-foreground">{d.rationale}</p>}
                {d.tool_call?.args && (
                  <pre className="mt-1 text-[10px] text-muted-foreground/80 truncate">{JSON.stringify(d.tool_call.args)}</pre>
                )}
              </div>
            ))}
          </div>
        </ScrollArea>

        <ScrollArea className="h-[320px] pr-3">
          <div className="space-y-1.5">
            {jobs.length === 0 && (
              <div className="text-xs text-muted-foreground">No detector jobs queued yet.</div>
            )}
            {jobs.map(j => (
              <div key={j.id} className="text-xs flex items-center gap-2 border border-border/50 rounded p-2 bg-background/40">
                {j.status === "running" && <Loader2 className="w-3 h-3 animate-spin text-yellow-500" />}
                {j.status === "completed" && <CheckCircle2 className="w-3 h-3 text-green-500" />}
                {j.status === "failed" && <AlertCircle className="w-3 h-3 text-red-500" />}
                {j.status === "pending" && <Cpu className="w-3 h-3 text-muted-foreground" />}
                <span className="font-mono">{j.detector}</span>
                <Badge variant="outline" className="ml-auto text-[10px]">{j.status}</Badge>
              </div>
            ))}
          </div>
        </ScrollArea>
      </div>
    </Card>
  );
}
