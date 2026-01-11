/**
 * Hook for managing real-time scan progress
 */

import { useState, useCallback, useRef } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useScanHistory } from "@/hooks/useScanHistory";
import type { ScanSession, ScanModule } from "@/components/ScanProgressDashboard";

interface UseScanProgressOptions {
  onComplete?: (session: ScanSession) => void;
  onError?: (error: Error) => void;
}

export const useScanProgress = (options?: UseScanProgressOptions) => {
  const [session, setSession] = useState<ScanSession | null>(null);
  const { logScan, completeScan, saveReport, createAlert } = useScanHistory();
  const abortRef = useRef(false);

  const normalizeHost = (raw: string) => raw.trim().replace(/^https?:\/\//, "").split("/")[0];
  const normalizeUrl = (raw: string) => {
    const t = raw.trim();
    if (t.startsWith("http://") || t.startsWith("https://")) return t;
    return `https://${normalizeHost(t)}`;
  };

  const updateModule = useCallback((moduleId: string, updates: Partial<ScanModule>) => {
    setSession(prev => {
      if (!prev) return null;
      return {
        ...prev,
        modules: prev.modules.map(m => m.id === moduleId ? { ...m, ...updates } : m),
        progress: prev.modules.reduce((sum, m) => {
          const mod = m.id === moduleId ? { ...m, ...updates } : m;
          return sum + (mod.status === 'completed' ? 100 : mod.status === 'failed' ? 100 : mod.progress);
        }, 0) / prev.modules.length,
        totalFindings: prev.modules.reduce((sum, m) => {
          const mod = m.id === moduleId ? { ...m, ...updates } : m;
          return sum + mod.findings;
        }, 0),
      };
    });
  }, []);

  const runModuleScan = async (
    module: ScanModule, 
    target: string, 
    host: string, 
    url: string
  ): Promise<{ data: any; findings: number }> => {
    const startTime = Date.now();
    
    try {
      updateModule(module.id, { status: 'running', progress: 10 });
      
      let response;
      let functionName = '';
      let body = {};

      switch (module.module) {
        case 'recon':
          functionName = 'recon';
          body = { target: host };
          break;
        case 'subdomain':
          functionName = 'subdomain-enum';
          body = { domain: host };
          break;
        case 'endpoint':
          functionName = 'endpoint-discovery';
          body = { target: url };
          break;
        case 'webapp':
          functionName = 'webapp-scan';
          body = { target: url };
          break;
        case 'api':
          functionName = 'api-security';
          body = { target: url, scanType: 'comprehensive' };
          break;
        case 'cloud':
          functionName = 'cloud-security';
          body = { provider: 'auto', target: host };
          break;
        case 'iam':
          functionName = 'iam-security';
          body = { target: host, scanType: 'full' };
          break;
        case 'vuln':
          functionName = 'vulnintel';
          body = { query: host };
          break;
        case 'autonomous':
          functionName = 'autonomous-attack';
          body = { target: host, objective: 'Full VAPT analysis' };
          break;
        default:
          throw new Error(`Unknown module: ${module.module}`);
      }

      updateModule(module.id, { progress: 30 });
      response = await supabase.functions.invoke(functionName, { body });
      updateModule(module.id, { progress: 70 });

      if (response.error) {
        throw response.error;
      }

      const data = response.data || {};
      let findings = 0;

      // Extract findings count based on module type
      switch (module.module) {
        case 'recon':
          findings = data?.ports?.length || 0;
          break;
        case 'subdomain':
          findings = data?.total || data?.subdomains?.length || 0;
          break;
        case 'endpoint':
          findings = data?.total || data?.endpoints?.length || 0;
          break;
        case 'webapp':
        case 'api':
        case 'cloud':
        case 'iam':
          findings = data?.findings?.length || 0;
          break;
        case 'vuln':
          findings = data?.count || data?.vulnerabilities?.length || 0;
          break;
        case 'autonomous':
          findings = data?.attack_chain?.length || data?.recommendations?.length || 0;
          break;
      }

      const duration = Date.now() - startTime;
      updateModule(module.id, { 
        status: 'completed', 
        progress: 100, 
        findings, 
        duration,
        details: data?.summary || `${findings} items found`
      });

      return { data, findings };
    } catch (error: any) {
      const duration = Date.now() - startTime;
      updateModule(module.id, { 
        status: 'failed', 
        progress: 100, 
        duration,
        error: error?.message || 'Scan failed'
      });
      throw error;
    }
  };

  const startRedTeamScan = useCallback(async (rawTarget: string) => {
    abortRef.current = false;
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    const modules: ScanModule[] = [
      { id: '1', name: 'Reconnaissance', module: 'recon', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '2', name: 'Subdomain Enumeration', module: 'subdomain', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '3', name: 'Endpoint Discovery', module: 'endpoint', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '4', name: 'Web Application Scan', module: 'webapp', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '5', name: 'API Security Test', module: 'api', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '6', name: 'Cloud Security Audit', module: 'cloud', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '7', name: 'IAM Security Check', module: 'iam', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '8', name: 'Vulnerability Intel', module: 'vuln', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '9', name: 'AI Attack Synthesis', module: 'autonomous', status: 'pending', progress: 0, findings: 0, duration: 0 },
    ];

    const newSession: ScanSession = {
      id: crypto.randomUUID(),
      target: host,
      type: 'Red Team VAPT',
      status: 'running',
      startTime: new Date(),
      modules,
      totalFindings: 0,
      progress: 0,
    };

    setSession(newSession);

    const results: Record<string, any> = {};
    let totalFindings = 0;

    try {
      // Phase 1: Recon + Subdomain (parallel)
      const [reconResult, subdomainResult] = await Promise.all([
        runModuleScan(modules[0], rawTarget, host, url),
        runModuleScan(modules[1], rawTarget, host, url),
      ]);
      results.recon = reconResult.data;
      results.subdomain = subdomainResult.data;
      totalFindings += reconResult.findings + subdomainResult.findings;

      if (abortRef.current) throw new Error('Scan aborted');

      // Phase 2: Endpoint Discovery
      const endpointResult = await runModuleScan(modules[2], rawTarget, host, url);
      results.endpoint = endpointResult.data;
      totalFindings += endpointResult.findings;

      if (abortRef.current) throw new Error('Scan aborted');

      // Phase 3: Web + Vuln (parallel)
      const [webResult, vulnResult] = await Promise.all([
        runModuleScan(modules[3], rawTarget, host, url),
        runModuleScan(modules[7], rawTarget, host, url),
      ]);
      results.webapp = webResult.data;
      results.vuln = vulnResult.data;
      totalFindings += webResult.findings + vulnResult.findings;

      if (abortRef.current) throw new Error('Scan aborted');

      // Phase 4: API + Cloud + IAM (parallel)
      const [apiResult, cloudResult, iamResult] = await Promise.all([
        runModuleScan(modules[4], rawTarget, host, url),
        runModuleScan(modules[5], rawTarget, host, url),
        runModuleScan(modules[6], rawTarget, host, url),
      ]);
      results.api = apiResult.data;
      results.cloud = cloudResult.data;
      results.iam = iamResult.data;
      totalFindings += apiResult.findings + cloudResult.findings + iamResult.findings;

      if (abortRef.current) throw new Error('Scan aborted');

      // Phase 5: AI Attack Synthesis
      const autonomousResult = await runModuleScan(modules[8], rawTarget, host, url);
      results.autonomous = autonomousResult.data;
      totalFindings += autonomousResult.findings;

      // Calculate severity counts
      const criticalCount = (results.webapp?.summary?.critical ?? 0) + (results.api?.summary?.critical ?? 0) + (results.cloud?.summary?.critical ?? 0);
      const highCount = (results.webapp?.summary?.high ?? 0) + (results.api?.summary?.high ?? 0);

      // Create alerts for critical findings
      if (criticalCount > 0) {
        await createAlert({
          type: 'red_team',
          severity: 'critical',
          title: `Red Team VAPT Complete: ${totalFindings} findings on ${host}`,
          description: `Critical: ${criticalCount} | High: ${highCount} | Target: ${host}`,
          sourceModule: 'red_team',
          target: host,
        });
      }

      // Save comprehensive report
      await saveReport({
        module: 'red_team',
        title: `Red Team VAPT Report - ${host}`,
        summary: `Total: ${totalFindings} findings across all modules`,
        findings: results,
        severityCounts: {
          critical: criticalCount,
          high: highCount,
          medium: results.webapp?.summary?.medium ?? 0,
          low: results.webapp?.summary?.low ?? 0,
        },
      });

      // Update session to completed
      setSession(prev => prev ? {
        ...prev,
        status: 'completed',
        endTime: new Date(),
        totalFindings,
        progress: 100,
      } : null);

      options?.onComplete?.(session!);

      return { success: true, totalFindings, results };
    } catch (error: any) {
      setSession(prev => prev ? {
        ...prev,
        status: 'failed',
        endTime: new Date(),
      } : null);
      options?.onError?.(error);
      return { success: false, error };
    }
  }, [updateModule, createAlert, saveReport, options, session]);

  const startDomainScan = useCallback(async (rawTarget: string) => {
    abortRef.current = false;
    const host = normalizeHost(rawTarget);
    const url = normalizeUrl(rawTarget);

    const modules: ScanModule[] = [
      { id: '1', name: 'Reconnaissance', module: 'recon', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '2', name: 'Web Application Scan', module: 'webapp', status: 'pending', progress: 0, findings: 0, duration: 0 },
      { id: '3', name: 'Vulnerability Intel', module: 'vuln', status: 'pending', progress: 0, findings: 0, duration: 0 },
    ];

    setSession({
      id: crypto.randomUUID(),
      target: host,
      type: 'Domain Scan',
      status: 'running',
      startTime: new Date(),
      modules,
      totalFindings: 0,
      progress: 0,
    });

    try {
      const [reconResult, webResult, vulnResult] = await Promise.all([
        runModuleScan(modules[0], rawTarget, host, url),
        runModuleScan(modules[1], rawTarget, host, url),
        runModuleScan(modules[2], rawTarget, host, url),
      ]);

      const totalFindings = reconResult.findings + webResult.findings + vulnResult.findings;

      setSession(prev => prev ? {
        ...prev,
        status: 'completed',
        endTime: new Date(),
        totalFindings,
        progress: 100,
      } : null);

      return { success: true, totalFindings };
    } catch (error: any) {
      setSession(prev => prev ? {
        ...prev,
        status: 'failed',
        endTime: new Date(),
      } : null);
      return { success: false, error };
    }
  }, [updateModule]);

  const abortScan = useCallback(() => {
    abortRef.current = true;
    setSession(prev => prev ? { ...prev, status: 'paused' } : null);
  }, []);

  const clearSession = useCallback(() => {
    setSession(null);
  }, []);

  return {
    session,
    startRedTeamScan,
    startDomainScan,
    abortScan,
    clearSession,
    updateModule,
  };
};

export default useScanProgress;
