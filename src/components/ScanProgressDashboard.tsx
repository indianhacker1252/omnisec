/**
 * Real-time Scan Progress Dashboard
 * Shows live status of each module during automated scans
 */

import { useState, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import {
  Activity,
  CheckCircle,
  XCircle,
  Clock,
  RefreshCw,
  AlertTriangle,
  Search,
  Globe,
  Network,
  Cloud,
  Key,
  Bug,
  Shield,
  Zap,
  Target,
  Layers,
  Eye,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

export interface ScanModule {
  id: string;
  name: string;
  module: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  progress: number;
  findings: number;
  duration: number;
  error?: string;
  details?: any;
}

export interface ScanSession {
  id: string;
  target: string;
  type: string;
  status: 'running' | 'completed' | 'failed' | 'paused';
  startTime: Date;
  endTime?: Date;
  modules: ScanModule[];
  totalFindings: number;
  progress: number;
}

interface ScanProgressDashboardProps {
  session?: ScanSession | null;
  onSessionUpdate?: (session: ScanSession) => void;
  compact?: boolean;
}

const MODULE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  recon: Search,
  subdomain: Layers,
  endpoint: Target,
  webapp: Globe,
  api: Network,
  cloud: Cloud,
  iam: Key,
  vuln: Bug,
  autonomous: Zap,
  report: Eye,
  default: Shield,
};

const MODULE_COLORS: Record<string, string> = {
  recon: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  subdomain: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  endpoint: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  webapp: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  api: 'bg-green-500/20 text-green-400 border-green-500/30',
  cloud: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
  iam: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  vuln: 'bg-red-500/20 text-red-400 border-red-500/30',
  autonomous: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  report: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

export const ScanProgressDashboard = ({ session, onSessionUpdate, compact = false }: ScanProgressDashboardProps) => {
  const [expanded, setExpanded] = useState(!compact);
  const [liveSessions, setLiveSessions] = useState<ScanSession[]>([]);

  // Subscribe to real-time scan updates
  useEffect(() => {
    const channel = supabase
      .channel('scan-progress')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scan_history',
        },
        (payload) => {
          // Update live sessions when scan_history changes
          if (payload.new && typeof payload.new === 'object') {
            const scan = payload.new as any;
            if (scan.status === 'in_progress') {
              setLiveSessions(prev => {
                const existing = prev.find(s => s.id === scan.id);
                if (existing) {
                  return prev.map(s => s.id === scan.id ? { ...s, progress: 50 } : s);
                }
                return prev;
              });
            }
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'running': return <RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'skipped': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getModuleIcon = (module: string) => {
    const Icon = MODULE_ICONS[module] || MODULE_ICONS.default;
    return <Icon className="h-4 w-4" />;
  };

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };

  const getOverallStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'border-green-500/50 bg-green-500/5';
      case 'failed': return 'border-red-500/50 bg-red-500/5';
      case 'running': return 'border-blue-500/50 bg-blue-500/5';
      case 'paused': return 'border-yellow-500/50 bg-yellow-500/5';
      default: return 'border-border/50 bg-background/50';
    }
  };

  if (!session && liveSessions.length === 0) {
    return (
      <Card className="p-4 bg-card/50 backdrop-blur border-primary/20">
        <div className="flex items-center gap-3">
          <Activity className="h-5 w-5 text-muted-foreground" />
          <div>
            <p className="text-sm font-medium">No Active Scans</p>
            <p className="text-xs text-muted-foreground">Start a scan from the AI Assistant or any module</p>
          </div>
        </div>
      </Card>
    );
  }

  const activeSession = session || liveSessions[0];

  return (
    <Card className={`bg-card/50 backdrop-blur ${getOverallStatusColor(activeSession?.status || 'pending')} transition-all duration-300`}>
      {/* Header */}
      <div 
        className="p-4 flex items-center justify-between cursor-pointer hover:bg-accent/5 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className="relative">
            <Activity className={`h-5 w-5 ${activeSession?.status === 'running' ? 'text-blue-500 animate-pulse' : 'text-primary'}`} />
            {activeSession?.status === 'running' && (
              <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-blue-500 animate-ping" />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-sm">
              {activeSession?.type || 'Security Scan'} 
              {activeSession?.target && <span className="text-muted-foreground ml-2">→ {activeSession.target}</span>}
            </h3>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant={activeSession?.status === 'running' ? 'default' : 'secondary'} className="text-xs">
                {activeSession?.status || 'pending'}
              </Badge>
              <span>{activeSession?.totalFindings || 0} findings</span>
              {activeSession?.startTime && (
                <span>Started: {new Date(activeSession.startTime).toLocaleTimeString()}</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 min-w-[120px]">
            <Progress value={activeSession?.progress || 0} className="h-2" />
            <span className="text-xs font-mono text-muted-foreground w-10">{activeSession?.progress?.toFixed(0) || 0}%</span>
          </div>
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && activeSession?.modules && (
        <div className="border-t border-border/50">
          <ScrollArea className="max-h-[300px]">
            <div className="p-4 space-y-2">
              {activeSession.modules.map((module, idx) => (
                <div
                  key={module.id || idx}
                  className={`p-3 rounded-lg border transition-all duration-300 ${
                    module.status === 'running' 
                      ? 'border-blue-500/50 bg-blue-500/10 shadow-lg shadow-blue-500/10' 
                      : module.status === 'completed'
                      ? 'border-green-500/30 bg-green-500/5'
                      : module.status === 'failed'
                      ? 'border-red-500/30 bg-red-500/5'
                      : 'border-border/30 bg-background/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground font-mono w-6">#{idx + 1}</span>
                      {getStatusIcon(module.status)}
                      <div className={`p-1.5 rounded ${MODULE_COLORS[module.module] || 'bg-gray-500/20 text-gray-400'}`}>
                        {getModuleIcon(module.module)}
                      </div>
                      <div>
                        <span className="font-medium text-sm">{module.name}</span>
                        {module.status === 'running' && (
                          <div className="flex items-center gap-2 mt-1">
                            <Progress value={module.progress} className="h-1 w-24" />
                            <span className="text-xs text-muted-foreground">{module.progress}%</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      {module.findings > 0 && (
                        <Badge variant={module.findings > 5 ? 'destructive' : 'secondary'} className="text-xs">
                          {module.findings} findings
                        </Badge>
                      )}
                      {module.duration > 0 && (
                        <span className="font-mono">{formatDuration(module.duration)}</span>
                      )}
                    </div>
                  </div>
                  {module.error && (
                    <p className="text-xs text-red-400 mt-2 pl-8">{module.error}</p>
                  )}
                  {module.status === 'completed' && module.details && (
                    <div className="text-xs text-muted-foreground mt-2 pl-8">
                      {typeof module.details === 'string' ? module.details : JSON.stringify(module.details).slice(0, 100)}...
                    </div>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>

          {/* Summary Footer */}
          {activeSession.status === 'completed' && (
            <div className="p-4 border-t border-green-500/20 bg-green-500/5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-green-400">
                  <CheckCircle className="h-5 w-5" />
                  <span className="font-semibold">Scan Complete</span>
                </div>
                <div className="text-sm text-muted-foreground">
                  {activeSession.modules.filter(m => m.status === 'completed').length}/{activeSession.modules.length} modules • 
                  {activeSession.totalFindings} total findings
                  {activeSession.endTime && activeSession.startTime && (
                    <> • {formatDuration(new Date(activeSession.endTime).getTime() - new Date(activeSession.startTime).getTime())}</>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeSession.status === 'failed' && (
            <div className="p-4 border-t border-red-500/20 bg-red-500/5">
              <div className="flex items-center gap-2 text-red-400">
                <XCircle className="h-5 w-5" />
                <span className="font-semibold">Scan Failed</span>
                <span className="text-sm text-muted-foreground ml-2">
                  {activeSession.modules.filter(m => m.status === 'failed').length} modules failed
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

export default ScanProgressDashboard;
