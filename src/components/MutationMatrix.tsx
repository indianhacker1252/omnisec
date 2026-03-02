/**
 * OmniSec™ Mutation Matrix — Real-time visualization of the payload mutation retry engine.
 * Shows the chain: Original Payload → [Block] → AI Mutation → Mutated Payload → [Result]
 */

import { useState, useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { supabase } from "@/integrations/supabase/client";
import {
  Zap, ShieldAlert, Brain, CheckCircle, XCircle, ArrowRight,
  RefreshCw, AlertTriangle, Activity, GitBranch, Clock, Shield
} from "lucide-react";

interface MutationEvent {
  type: 'MUTATION_START' | 'MUTATION_SUCCESS' | 'MUTATION_FAIL' | 'MAX_RETRIES_REACHED';
  data: any;
  timestamp: number;
  id: string;
}

interface MutationChainDisplay {
  chainId: string;
  parameter: string;
  targetUrl: string;
  attempts: Array<{
    payload: string;
    status: number;
    blocked: boolean;
    isOriginal?: boolean;
    isMutation?: boolean;
    isSuccess?: boolean;
    isFinal?: boolean;
  }>;
  status: 'active' | 'success' | 'defended';
}

interface MutationMatrixProps {
  scanId?: string;
  isActive?: boolean;
}

export const MutationMatrix = ({ scanId, isActive }: MutationMatrixProps) => {
  const [events, setEvents] = useState<MutationEvent[]>([]);
  const [chains, setChains] = useState<Map<string, MutationChainDisplay>>(new Map());
  const [stats, setStats] = useState({
    totalMutations: 0,
    wafBypasses: 0,
    defended: 0,
    active: 0,
  });
  const scrollRef = useRef<HTMLDivElement>(null);

  // Listen for mutation events via realtime
  useEffect(() => {
    if (!isActive) return;

    const channel = supabase
      .channel(`mutation-events-${Date.now()}`)
      .on("postgres_changes", {
        event: "INSERT",
        schema: "public",
        table: "scan_progress",
      }, (payload: any) => {
        const data = payload.new;
        if (!data.message?.startsWith('🧬 ')) return;

        try {
          const typeMatch = data.message.match(/🧬 (\w+): (.*)/);
          if (!typeMatch) return;

          const [, eventType, jsonStr] = typeMatch;
          const eventData = JSON.parse(jsonStr);

          const event: MutationEvent = {
            type: eventType as any,
            data: eventData,
            timestamp: Date.now(),
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          };

          setEvents(prev => [...prev, event]);

          // Update chain visualization
          setChains(prev => {
            const next = new Map(prev);
            const chainId = eventData.chainId || eventData.parameter || 'unknown';
            const existing = next.get(chainId) || {
              chainId,
              parameter: eventData.parameter || '',
              targetUrl: eventData.targetUrl || '',
              attempts: [],
              status: 'active' as const,
            };

            switch (eventType) {
              case 'MUTATION_START':
                existing.attempts.push({
                  payload: eventData.originalPayload || '',
                  status: 403,
                  blocked: true,
                  isMutation: true,
                });
                existing.status = 'active';
                break;
              case 'MUTATION_SUCCESS':
                existing.attempts.push({
                  payload: eventData.payload || '',
                  status: eventData.status || 200,
                  blocked: false,
                  isSuccess: true,
                  isFinal: true,
                });
                existing.status = 'success';
                break;
              case 'MAX_RETRIES_REACHED':
                existing.attempts.push({
                  payload: eventData.payload || '',
                  status: 403,
                  blocked: true,
                  isFinal: true,
                });
                existing.status = 'defended';
                break;
              case 'MUTATION_FAIL':
                existing.attempts.push({
                  payload: '[AI Error]',
                  status: -1,
                  blocked: true,
                  isMutation: true,
                });
                break;
            }

            next.set(chainId, existing);
            return next;
          });

          // Update stats
          setStats(prev => ({
            totalMutations: prev.totalMutations + (eventType === 'MUTATION_START' ? 1 : 0),
            wafBypasses: prev.wafBypasses + (eventType === 'MUTATION_SUCCESS' ? 1 : 0),
            defended: prev.defended + (eventType === 'MAX_RETRIES_REACHED' ? 1 : 0),
            active: Math.max(0, prev.active + (eventType === 'MUTATION_START' ? 1 : 0) - (eventType === 'MUTATION_SUCCESS' || eventType === 'MAX_RETRIES_REACHED' ? 1 : 0)),
          }));

        } catch {}
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [isActive]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  const chainArray = Array.from(chains.values());

  return (
    <Card className="p-4 border-primary/20">
      <div className="flex items-center gap-2 mb-4">
        <div className="p-2 bg-primary/10 rounded-lg">
          <GitBranch className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h3 className="font-bold text-sm">Mutation Matrix</h3>
          <p className="text-[10px] text-muted-foreground">AI-powered payload mutation & WAF bypass engine</p>
        </div>
        {isActive && <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse ml-auto" />}
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-2 mb-4">
        {[
          { label: "Mutations", value: stats.totalMutations, icon: <Brain className="h-3 w-3" />, cls: "text-primary" },
          { label: "WAF Bypassed", value: stats.wafBypasses, icon: <Zap className="h-3 w-3" />, cls: "text-green-400" },
          { label: "Defended", value: stats.defended, icon: <Shield className="h-3 w-3" />, cls: "text-orange-400" },
          { label: "Active", value: stats.active, icon: <Activity className="h-3 w-3 animate-pulse" />, cls: "text-yellow-400" },
        ].map(s => (
          <div key={s.label} className="text-center p-2 bg-background/50 rounded border border-border/30">
            <div className={`text-lg font-bold ${s.cls}`}>{s.value}</div>
            <div className="text-[10px] text-muted-foreground flex items-center justify-center gap-1">{s.icon}{s.label}</div>
          </div>
        ))}
      </div>

      {/* Chain visualization */}
      <ScrollArea className="h-64">
        <div className="space-y-3">
          {chainArray.length === 0 && (
            <div className="text-center text-muted-foreground py-8">
              <GitBranch className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-xs">Mutation chains appear here when WAF blocks payloads</p>
            </div>
          )}

          {chainArray.map((chain) => (
            <div key={chain.chainId} className={`p-3 rounded-lg border transition-colors ${
              chain.status === 'success' ? 'border-green-500/30 bg-green-500/5' :
              chain.status === 'defended' ? 'border-orange-500/30 bg-orange-500/5' :
              'border-primary/30 bg-primary/5'
            }`}>
              {/* Chain header */}
              <div className="flex items-center gap-2 mb-2">
                <Badge variant="outline" className="text-[10px] font-mono">{chain.parameter}</Badge>
                {chain.status === 'success' && <Badge className="bg-green-500/20 text-green-400 text-[10px] border-green-500/30">WAF BYPASSED</Badge>}
                {chain.status === 'defended' && <Badge className="bg-orange-500/20 text-orange-400 text-[10px] border-orange-500/30">DEFENDED</Badge>}
                {chain.status === 'active' && <Badge className="bg-primary/20 text-primary text-[10px] border-primary/30 animate-pulse">MUTATING...</Badge>}
                <span className="text-[10px] text-muted-foreground ml-auto">{chain.attempts.length} attempt{chain.attempts.length !== 1 ? 's' : ''}</span>
              </div>

              {/* Timeline visualization */}
              <div className="flex items-center gap-1 flex-wrap">
                {chain.attempts.map((attempt, i) => (
                  <div key={i} className="flex items-center gap-1">
                    {i > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
                    <div className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono ${
                      attempt.isSuccess ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                      attempt.blocked ? 'bg-destructive/20 text-destructive border border-destructive/30' :
                      'bg-muted text-muted-foreground border border-border/30'
                    }`}>
                      {attempt.blocked && !attempt.isFinal && <ShieldAlert className="h-3 w-3 shrink-0" />}
                      {attempt.isSuccess && <CheckCircle className="h-3 w-3 shrink-0" />}
                      {attempt.isFinal && attempt.blocked && <XCircle className="h-3 w-3 shrink-0" />}
                      {attempt.isMutation && !attempt.isFinal && <Brain className="h-3 w-3 shrink-0 animate-pulse" />}
                      <span className="max-w-[120px] truncate">{attempt.payload}</span>
                      {attempt.status > 0 && <span className="opacity-60">[{attempt.status}]</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          <div ref={scrollRef} />
        </div>
      </ScrollArea>

      {/* Recent event log */}
      {events.length > 0 && (
        <div className="mt-3 pt-3 border-t border-border/30">
          <div className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
            <Clock className="h-3 w-3" /> Recent Events
          </div>
          <div className="space-y-1 max-h-24 overflow-auto">
            {events.slice(-5).map(e => (
              <div key={e.id} className="flex items-center gap-2 text-[10px]">
                <span className="text-muted-foreground shrink-0">
                  {new Date(e.timestamp).toLocaleTimeString()}
                </span>
                {e.type === 'MUTATION_START' && <RefreshCw className="h-3 w-3 text-yellow-400 shrink-0" />}
                {e.type === 'MUTATION_SUCCESS' && <CheckCircle className="h-3 w-3 text-green-400 shrink-0" />}
                {e.type === 'MAX_RETRIES_REACHED' && <AlertTriangle className="h-3 w-3 text-orange-400 shrink-0" />}
                {e.type === 'MUTATION_FAIL' && <XCircle className="h-3 w-3 text-destructive shrink-0" />}
                <span className={
                  e.type === 'MUTATION_SUCCESS' ? 'text-green-400' :
                  e.type === 'MAX_RETRIES_REACHED' ? 'text-orange-400' :
                  e.type === 'MUTATION_FAIL' ? 'text-destructive' : 'text-muted-foreground'
                }>
                  {e.type.replace(/_/g, ' ')}
                </span>
                <span className="text-muted-foreground truncate">{e.data?.parameter || ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
};
