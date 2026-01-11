/**
 * Global Scan Progress Context
 * Provides scan progress state across all components
 */

import { createContext, useContext, useState, useCallback, ReactNode } from "react";
import type { ScanSession, ScanModule } from "@/components/ScanProgressDashboard";

interface ScanProgressContextType {
  session: ScanSession | null;
  setSession: (session: ScanSession | null) => void;
  updateModule: (moduleId: string, updates: Partial<ScanModule>) => void;
  isScanning: boolean;
}

const ScanProgressContext = createContext<ScanProgressContextType | undefined>(undefined);

export const ScanProgressProvider = ({ children }: { children: ReactNode }) => {
  const [session, setSessionState] = useState<ScanSession | null>(null);

  const setSession = useCallback((newSession: ScanSession | null) => {
    setSessionState(newSession);
  }, []);

  const updateModule = useCallback((moduleId: string, updates: Partial<ScanModule>) => {
    setSessionState(prev => {
      if (!prev) return null;
      const updatedModules = prev.modules.map(m => 
        m.id === moduleId ? { ...m, ...updates } : m
      );
      const progress = updatedModules.reduce((sum, m) => {
        return sum + (m.status === 'completed' || m.status === 'failed' ? 100 : m.progress);
      }, 0) / updatedModules.length;
      const totalFindings = updatedModules.reduce((sum, m) => sum + m.findings, 0);

      return {
        ...prev,
        modules: updatedModules,
        progress,
        totalFindings,
      };
    });
  }, []);

  const isScanning = session?.status === 'running';

  return (
    <ScanProgressContext.Provider value={{ session, setSession, updateModule, isScanning }}>
      {children}
    </ScanProgressContext.Provider>
  );
};

export const useScanProgressContext = () => {
  const context = useContext(ScanProgressContext);
  if (!context) {
    throw new Error('useScanProgressContext must be used within a ScanProgressProvider');
  }
  return context;
};
