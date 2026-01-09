/**
 * OmniSec™ Command Header
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { Bell, Settings, Terminal, LogOut, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect, useCallback } from "react";
import { supabase } from "@/integrations/supabase/client";

interface SecurityAlert {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  type: string;
  source_module: string | null;
  target: string | null;
  created_at: string;
  is_read: boolean | null;
}

export const CommandHeader = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('security_alerts')
        .select('*')
        .eq('is_cleared', false)
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) throw error;
      setAlerts((data as SecurityAlert[]) || []);
    } catch (e) {
      console.error('Failed to fetch alerts:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();

    // Subscribe to real-time alert updates
    const channel = supabase
      .channel('security_alerts_changes')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'security_alerts' }, () => {
        fetchAlerts();
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [fetchAlerts]);

  const unreadCount = alerts.filter(a => !a.is_read).length;

  const handleClearAlerts = async () => {
    try {
      const { error } = await supabase
        .from('security_alerts')
        .update({ is_cleared: true, cleared_at: new Date().toISOString() })
        .eq('is_cleared', false);

      if (error) throw error;

      setAlerts([]);
      toast({
        title: "Alerts Cleared",
        description: "All notifications have been cleared",
      });
    } catch (e) {
      console.error('Failed to clear alerts:', e);
      toast({
        title: "Error",
        description: "Failed to clear alerts",
        variant: "destructive",
      });
    }
  };

  const handleMarkAsRead = async (alertId: string) => {
    try {
      await supabase
        .from('security_alerts')
        .update({ is_read: true })
        .eq('id', alertId);

      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, is_read: true } : a));
    } catch (e) {
      console.error('Failed to mark alert as read:', e);
    }
  };

  const handleSignOut = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      toast({
        title: "Error",
        description: "Failed to sign out",
        variant: "destructive",
      });
    } else {
      toast({
        title: "Signed Out",
        description: "You have been signed out successfully",
      });
      navigate("/auth");
    }
  };

  const getSeverityVariant = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'destructive';
      case 'high': return 'default';
      case 'medium': return 'secondary';
      default: return 'outline';
    }
  };

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <Terminal className="h-6 w-6 text-cyber-green" />
          <div>
            <h1 className="text-lg font-bold font-mono leading-none">
              OmniSec<sup className="text-[8px] align-super">TM</sup>
            </h1>
            <p className="text-[10px] text-muted-foreground">
              © HARSH MALIK
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <Bell className="h-5 w-5" />
                {unreadCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-[10px]"
                  >
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-96">
              <DropdownMenuLabel className="flex items-center justify-between">
                <span>Security Alerts</span>
                <div className="flex gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0"
                    onClick={fetchAlerts}
                    disabled={loading}
                  >
                    <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
                  </Button>
                  {alerts.length > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={handleClearAlerts}
                    >
                      Clear All
                    </Button>
                  )}
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {alerts.length > 0 ? (
                alerts.map((alert) => (
                  <DropdownMenuItem
                    key={alert.id}
                    className={`flex flex-col items-start gap-1 p-3 cursor-pointer ${!alert.is_read ? 'bg-muted/50' : ''}`}
                    onClick={() => handleMarkAsRead(alert.id)}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-2">
                        <Badge variant={getSeverityVariant(alert.severity) as any} className="text-[10px]">
                          {alert.severity.toUpperCase()}
                        </Badge>
                        {alert.source_module && (
                          <span className="text-[10px] text-muted-foreground">{alert.source_module}</span>
                        )}
                      </div>
                      <span className="text-[10px] text-muted-foreground">{formatTime(alert.created_at)}</span>
                    </div>
                    <span className="text-sm font-medium">{alert.title}</span>
                    {alert.description && (
                      <span className="text-xs text-muted-foreground line-clamp-2">{alert.description}</span>
                    )}
                    {alert.target && (
                      <span className="text-[10px] text-cyber-cyan font-mono">Target: {alert.target}</span>
                    )}
                  </DropdownMenuItem>
                ))
              ) : (
                <div className="p-4 text-center text-sm text-muted-foreground">
                  {loading ? 'Loading alerts...' : 'No active alerts'}
                </div>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/settings")}
          >
            <Settings className="h-5 w-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={handleSignOut}
            title="Sign Out"
          >
            <LogOut className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  );
};