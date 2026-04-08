/**
 * BackgroundScanContext — persists active scan state across route changes.
 * Wraps entire app so navigating away from the VAPT dashboard doesn't lose scan progress.
 */
import { createContext, useContext, useState, useCallback, useRef, useEffect, ReactNode } from "react";
import { supabase } from "@/integrations/supabase/client";

interface BackgroundScan {
  scanId: string;
  target: string;
  progress: number;
  phase: string;
  findings: number;
  endpoints: number;
  status: "running" | "completed" | "failed";
  startedAt: Date;
}

interface BackgroundScanContextType {
  activeScan: BackgroundScan | null;
  setActiveScan: (scan: BackgroundScan | null) => void;
  updateScanProgress: (updates: Partial<BackgroundScan>) => void;
  completedScanIds: string[];
  addCompletedScan: (scanId: string) => void;
}

const BackgroundScanContext = createContext<BackgroundScanContextType | undefined>(undefined);

export const BackgroundScanProvider = ({ children }: { children: ReactNode }) => {
  const [activeScan, setActiveScanState] = useState<BackgroundScan | null>(null);
  const [completedScanIds, setCompletedScanIds] = useState<string[]>([]);
  const channelRef = useRef<any>(null);

  const setActiveScan = useCallback((scan: BackgroundScan | null) => {
    setActiveScanState(scan);
  }, []);

  const updateScanProgress = useCallback((updates: Partial<BackgroundScan>) => {
    setActiveScanState(prev => prev ? { ...prev, ...updates } : null);
  }, []);

  const addCompletedScan = useCallback((scanId: string) => {
    setCompletedScanIds(prev => prev.includes(scanId) ? prev : [scanId, ...prev].slice(0, 50));
    setActiveScanState(prev => prev?.scanId === scanId ? { ...prev, status: "completed", progress: 100 } : prev);
  }, []);

  // Global realtime listener for active scans
  useEffect(() => {
    if (!activeScan?.scanId || activeScan.status !== "running") return;

    const channel = supabase
      .channel(`bg-scan-${activeScan.scanId}-${Date.now()}`)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "scan_progress" }, (payload: any) => {
        const data = payload.new;
        if (data.scan_id !== activeScan.scanId) return;
        updateScanProgress({
          progress: data.progress >= 0 ? data.progress : activeScan.progress,
          phase: data.phase || activeScan.phase,
          findings: data.findings_so_far || activeScan.findings,
          endpoints: data.endpoints_discovered || activeScan.endpoints,
        });
        if (data.phase === "complete" || data.progress >= 100) {
          addCompletedScan(activeScan.scanId);
        }
      })
      .on("postgres_changes", { event: "UPDATE", schema: "public", table: "scan_history" }, (payload: any) => {
        const data = payload.new;
        if (data.id !== activeScan.scanId) return;
        if (data.status === "completed") addCompletedScan(activeScan.scanId);
        if (data.status === "failed") updateScanProgress({ status: "failed" });
      })
      .subscribe();

    channelRef.current = channel;
    return () => { supabase.removeChannel(channel); };
  }, [activeScan?.scanId, activeScan?.status]);

  return (
    <BackgroundScanContext.Provider value={{ activeScan, setActiveScan, updateScanProgress, completedScanIds, addCompletedScan }}>
      {children}
    </BackgroundScanContext.Provider>
  );
};

export const useBackgroundScan = () => {
  const context = useContext(BackgroundScanContext);
  if (!context) throw new Error("useBackgroundScan must be used within BackgroundScanProvider");
  return context;
};
