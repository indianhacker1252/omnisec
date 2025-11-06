import { Button } from "@/components/ui/button";
import { Download, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface ReportData {
  target: string;
  scanType: string;
  timestamp: string;
  findings: any[];
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface ReportGeneratorProps {
  data: ReportData;
}

export const ReportGenerator = ({ data }: ReportGeneratorProps) => {
  const { toast } = useToast();

  const generateHTMLReport = () => {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniSec™ Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; border-radius: 8px; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .meta-item { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }
        .meta-item label { font-weight: bold; color: #666; display: block; margin-bottom: 5px; font-size: 0.9em; }
        .meta-item value { font-size: 1.2em; color: #333; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; color: white; }
        .summary-card.critical { background: #dc3545; }
        .summary-card.high { background: #fd7e14; }
        .summary-card.medium { background: #ffc107; color: #333; }
        .summary-card.low { background: #17a2b8; }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { font-size: 0.9em; opacity: 0.9; }
        .findings { margin-top: 30px; }
        .finding { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid #667eea; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #17a2b8; }
        .finding-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }
        .finding-title { font-size: 1.3em; font-weight: bold; color: #333; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }
        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high { background: #fd7e14; color: white; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #17a2b8; color: white; }
        .finding-description { color: #666; margin-bottom: 15px; line-height: 1.8; }
        .finding-details { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .footer { text-align: center; padding: 30px; color: #666; border-top: 2px solid #dee2e6; margin-top: 40px; }
        @media print { body { background: white; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ OmniSec™ Security Assessment Report</h1>
            <p>Advanced Vulnerability Assessment & Penetration Testing</p>
        </div>

        <div class="meta">
            <div class="meta-item">
                <label>Target</label>
                <value>${data.target}</value>
            </div>
            <div class="meta-item">
                <label>Scan Type</label>
                <value>${data.scanType}</value>
            </div>
            <div class="meta-item">
                <label>Timestamp</label>
                <value>${new Date(data.timestamp).toLocaleString()}</value>
            </div>
            <div class="meta-item">
                <label>Total Findings</label>
                <value>${data.findings.length}</value>
            </div>
        </div>

        ${data.summary ? `
        <h2 style="margin-bottom: 20px; color: #333;">📊 Executive Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <div class="count">${data.summary.critical || 0}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">${data.summary.high || 0}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">${data.summary.medium || 0}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">${data.summary.low || 0}</div>
                <div class="label">Low</div>
            </div>
        </div>
        ` : ''}

        <h2 style="margin: 30px 0 20px 0; color: #333;">🔍 Detailed Findings</h2>
        <div class="findings">
            ${data.findings.map((finding: any, index: number) => `
                <div class="finding ${finding.severity || 'info'}">
                    <div class="finding-header">
                        <div class="finding-title">${index + 1}. ${finding.title || finding.name || 'Unnamed Finding'}</div>
                        <span class="severity-badge ${finding.severity || 'info'}">${finding.severity || 'info'}</span>
                    </div>
                    <div class="finding-description">
                        ${finding.description || 'No description available'}
                    </div>
                    ${finding.url || finding.cwe || finding.method ? `
                    <div class="finding-details">
                        ${finding.url ? `<div><strong>URL:</strong> ${finding.url}</div>` : ''}
                        ${finding.method ? `<div><strong>Method:</strong> ${finding.method}</div>` : ''}
                        ${finding.cwe ? `<div><strong>CWE:</strong> ${finding.cwe}</div>` : ''}
                    </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>

        <div class="footer">
            <p><strong>OmniSec™ - Advanced VAPT Platform</strong></p>
            <p>© 2024 HARSH MALIK. All Rights Reserved. | Patent Pending</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                ⚠️ This report contains confidential security information. Handle with appropriate care.
            </p>
        </div>
    </div>
</body>
</html>
    `;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OmniSec_Report_${data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Report Generated",
      description: "Security assessment report downloaded successfully",
    });
  };

  const generateJSONReport = () => {
    const report = {
      meta: {
        tool: "OmniSec™ VAPT Platform",
        version: "1.0.0",
        target: data.target,
        scanType: data.scanType,
        timestamp: data.timestamp,
        generatedAt: new Date().toISOString(),
      },
      summary: data.summary || {
        total: data.findings.length,
        critical: data.findings.filter((f: any) => f.severity === 'critical').length,
        high: data.findings.filter((f: any) => f.severity === 'high').length,
        medium: data.findings.filter((f: any) => f.severity === 'medium').length,
        low: data.findings.filter((f: any) => f.severity === 'low').length,
      },
      findings: data.findings,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OmniSec_Report_${data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "JSON Report Generated",
      description: "Raw data exported successfully",
    });
  };

  return (
    <div className="flex gap-2">
      <Button onClick={generateHTMLReport} variant="outline" className="gap-2">
        <FileText className="h-4 w-4" />
        Export HTML Report
      </Button>
      <Button onClick={generateJSONReport} variant="outline" className="gap-2">
        <Download className="h-4 w-4" />
        Export JSON
      </Button>
    </div>
  );
};
