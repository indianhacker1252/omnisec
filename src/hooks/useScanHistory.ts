import { supabase } from "@/integrations/supabase/client";

interface ScanResult {
  module: string;
  scanType: string;
  target?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  findingsCount?: number;
  report?: any;
  alertData?: {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
  }[];
}

export const useScanHistory = () => {

  const logScan = async (params: {
    module: string;
    scanType: string;
    target?: string;
  }) => {
    const { data, error } = await supabase
      .from('scan_history')
      .insert({
        module: params.module,
        scan_type: params.scanType,
        target: params.target || null,
        status: 'running',
        started_at: new Date().toISOString()
      })
      .select()
      .single();

    if (error) {
      console.error('Error logging scan start:', error);
      return null;
    }

    return data?.id;
  };

  const completeScan = async (scanId: string, result: {
    status: 'completed' | 'failed';
    findingsCount?: number;
    report?: any;
  }) => {
    const startedAt = new Date();
    
    const { error } = await supabase
      .from('scan_history')
      .update({
        status: result.status,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - startedAt.getTime(),
        findings_count: result.findingsCount || 0,
        report: result.report || null
      })
      .eq('id', scanId);

    if (error) {
      console.error('Error completing scan:', error);
    }
  };

  const createAlert = async (params: {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description?: string;
    sourceModule: string;
    target?: string;
  }) => {
    const { error } = await supabase
      .from('security_alerts')
      .insert({
        type: params.type,
        severity: params.severity,
        title: params.title,
        description: params.description || null,
        source_module: params.sourceModule,
        target: params.target || null
      });

    if (error) {
      console.error('Error creating alert:', error);
    }
  };

  const saveReport = async (params: {
    scanId?: string;
    module: string;
    title: string;
    summary?: string;
    findings?: any;
    recommendations?: any;
    severityCounts?: any;
  }) => {
    const { data, error } = await supabase
      .from('security_reports')
      .insert({
        scan_id: params.scanId || null,
        module: params.module,
        title: params.title,
        summary: params.summary || null,
        findings: params.findings || null,
        recommendations: params.recommendations || null,
        severity_counts: params.severityCounts || null
      })
      .select()
      .single();

    if (error) {
      console.error('Error saving report:', error);
      return null;
    }

    return data;
  };

  const getModuleHistory = async (module: string) => {
    const { data, error } = await supabase
      .from('scan_history')
      .select('*')
      .eq('module', module)
      .order('created_at', { ascending: false })
      .limit(20);

    if (error) {
      console.error('Error fetching module history:', error);
      return [];
    }

    return data || [];
  };

  const getModuleReports = async (module: string) => {
    const { data, error } = await supabase
      .from('security_reports')
      .select('*')
      .eq('module', module)
      .order('created_at', { ascending: false })
      .limit(10);

    if (error) {
      console.error('Error fetching module reports:', error);
      return [];
    }

    return data || [];
  };

  return {
    logScan,
    completeScan,
    createAlert,
    saveReport,
    getModuleHistory,
    getModuleReports
  };
};