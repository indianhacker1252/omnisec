/**
 * OmniSec™ PDF Report Generator
 * Professional security assessment report generation with proper PDF export
 */

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Download,
  Printer,
  FileDown,
  Loader2,
  CheckCircle,
  AlertTriangle
} from "lucide-react";

interface Finding {
  id?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  impact?: string;
  remediation?: string;
  cvss?: number;
  cwe?: string;
  endpoint?: string;
  evidence?: string;
  references?: string[];
}

interface ReportData {
  title: string;
  target: string;
  client?: string;
  assessor?: string;
  date: string;
  scope?: string[];
  methodology?: string;
  executiveSummary?: string;
  findings: Finding[];
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
  };
  recommendations?: string[];
  appendix?: any;
}

interface PDFReportGeneratorProps {
  data?: ReportData;
  findings?: Finding[];
}

export const PDFReportGenerator = ({ data, findings: propFindings }: PDFReportGeneratorProps) => {
  const { toast } = useToast();
  const [isGenerating, setIsGenerating] = useState(false);
  const [reportTitle, setReportTitle] = useState(data?.title || 'Security Assessment Report');
  const [clientName, setClientName] = useState(data?.client || '');
  const [assessorName, setAssessorName] = useState(data?.assessor || 'OmniSec VAPT Platform');
  const [reportFormat, setReportFormat] = useState<'detailed' | 'executive' | 'technical'>('detailed');

  const actualFindings = propFindings || data?.findings || [];
  const severityCounts = data?.severityCounts || {
    critical: actualFindings.filter(f => f.severity === 'critical').length,
    high: actualFindings.filter(f => f.severity === 'high').length,
    medium: actualFindings.filter(f => f.severity === 'medium').length,
    low: actualFindings.filter(f => f.severity === 'low').length,
    info: actualFindings.filter(f => f.severity === 'info').length,
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#ca8a04';
      case 'low': return '#2563eb';
      case 'info': return '#6b7280';
      default: return '#6b7280';
    }
  };

  const generatePDFContent = (): string => {
    const now = new Date();
    const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    const renderFinding = (finding: Finding, index: number): string => {
      return `
        <div class="finding" style="break-inside: avoid; page-break-inside: avoid; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
          <div class="finding-header" style="background: ${getSeverityColor(finding.severity)}; color: white; padding: 12px 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <strong style="font-size: 14px;">${index + 1}. ${finding.title}</strong>
              <span style="background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 12px; text-transform: uppercase;">
                ${finding.severity}
              </span>
            </div>
          </div>
          <div class="finding-body" style="padding: 16px;">
            ${finding.endpoint ? `
              <div style="margin-bottom: 12px;">
                <strong style="color: #374151;">Affected Endpoint:</strong>
                <code style="display: block; background: #f3f4f6; padding: 8px; border-radius: 4px; margin-top: 4px; font-family: monospace; word-break: break-all;">${finding.endpoint}</code>
              </div>
            ` : ''}
            
            <div style="margin-bottom: 12px;">
              <strong style="color: #374151;">Description:</strong>
              <p style="margin-top: 4px; color: #4b5563;">${finding.description}</p>
            </div>
            
            ${finding.impact ? `
              <div style="margin-bottom: 12px;">
                <strong style="color: #374151;">Impact:</strong>
                <p style="margin-top: 4px; color: #4b5563;">${finding.impact}</p>
              </div>
            ` : ''}
            
            ${finding.remediation ? `
              <div style="margin-bottom: 12px; background: #f0fdf4; padding: 12px; border-radius: 6px; border-left: 4px solid #22c55e;">
                <strong style="color: #166534;">Remediation:</strong>
                <p style="margin-top: 4px; color: #166534;">${finding.remediation}</p>
              </div>
            ` : ''}
            
            <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px;">
              ${finding.cvss ? `<span style="background: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 4px; font-size: 12px;">CVSS: ${finding.cvss}</span>` : ''}
              ${finding.cwe ? `<span style="background: #e0e7ff; color: #3730a3; padding: 4px 8px; border-radius: 4px; font-size: 12px;">${finding.cwe}</span>` : ''}
            </div>
            
            ${finding.evidence ? `
              <div style="margin-top: 12px;">
                <strong style="color: #374151;">Evidence:</strong>
                <pre style="background: #1f2937; color: #e5e7eb; padding: 12px; border-radius: 6px; margin-top: 4px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;">${finding.evidence}</pre>
              </div>
            ` : ''}
            
            ${finding.references && finding.references.length > 0 ? `
              <div style="margin-top: 12px;">
                <strong style="color: #374151;">References:</strong>
                <ul style="margin-top: 4px; padding-left: 20px; color: #6366f1;">
                  ${finding.references.map(ref => `<li style="margin-bottom: 4px;"><a href="${ref}" style="color: #6366f1; text-decoration: underline;">${ref}</a></li>`).join('')}
                </ul>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    };

    const executiveSummary = data?.executiveSummary || `
      This security assessment was conducted on ${data?.target || 'the target system'} to identify vulnerabilities 
      and security weaknesses. The assessment discovered a total of ${actualFindings.length} findings, 
      including ${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, 
      and ${severityCounts.low} low severity issues. Immediate attention is required for critical and high severity 
      vulnerabilities to maintain the security posture of the organization.
    `;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportTitle}</title>
  <style>
    @page {
      size: A4;
      margin: 20mm;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif;
      color: #1f2937;
      line-height: 1.6;
      font-size: 11pt;
    }
    
    .cover-page {
      height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4338ca 100%);
      color: white;
      page-break-after: always;
    }
    
    .cover-logo {
      font-size: 48pt;
      margin-bottom: 20px;
    }
    
    .cover-title {
      font-size: 28pt;
      font-weight: bold;
      margin-bottom: 10px;
    }
    
    .cover-subtitle {
      font-size: 14pt;
      opacity: 0.9;
      margin-bottom: 40px;
    }
    
    .cover-meta {
      font-size: 11pt;
      opacity: 0.8;
    }
    
    .cover-meta div {
      margin: 8px 0;
    }
    
    .section {
      margin-bottom: 30px;
    }
    
    .section-title {
      font-size: 16pt;
      font-weight: bold;
      color: #4338ca;
      border-bottom: 2px solid #4338ca;
      padding-bottom: 8px;
      margin-bottom: 16px;
    }
    
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    
    .summary-card {
      padding: 16px;
      border-radius: 8px;
      text-align: center;
    }
    
    .summary-card.critical { background: #fef2f2; border: 2px solid #dc2626; }
    .summary-card.high { background: #fff7ed; border: 2px solid #ea580c; }
    .summary-card.medium { background: #fefce8; border: 2px solid #ca8a04; }
    .summary-card.low { background: #eff6ff; border: 2px solid #2563eb; }
    
    .summary-count {
      font-size: 32pt;
      font-weight: bold;
    }
    
    .summary-label {
      font-size: 10pt;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 4px;
    }
    
    .summary-card.critical .summary-count { color: #dc2626; }
    .summary-card.high .summary-count { color: #ea580c; }
    .summary-card.medium .summary-count { color: #ca8a04; }
    .summary-card.low .summary-count { color: #2563eb; }
    
    .toc {
      page-break-after: always;
    }
    
    .toc-item {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px dotted #d1d5db;
    }
    
    .findings-section {
      page-break-before: always;
    }
    
    .footer {
      text-align: center;
      padding: 20px;
      color: #6b7280;
      font-size: 9pt;
      border-top: 1px solid #e5e7eb;
      margin-top: 40px;
    }
    
    .watermark {
      position: fixed;
      bottom: 10px;
      right: 10px;
      font-size: 8pt;
      color: #d1d5db;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
    }
    
    th, td {
      padding: 10px;
      border: 1px solid #e5e7eb;
      text-align: left;
    }
    
    th {
      background: #f3f4f6;
      font-weight: 600;
    }
    
    @media print {
      .no-print { display: none; }
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="cover-page">
    <div class="cover-logo">🛡️</div>
    <div class="cover-title">OmniSec™</div>
    <div class="cover-subtitle">Enterprise Security Assessment Report</div>
    <div style="width: 200px; height: 2px; background: rgba(255,255,255,0.3); margin: 20px 0;"></div>
    <h1 style="font-size: 22pt; margin: 20px 0;">${reportTitle}</h1>
    <div class="cover-meta">
      <div><strong>Target:</strong> ${data?.target || 'N/A'}</div>
      <div><strong>Client:</strong> ${clientName || 'N/A'}</div>
      <div><strong>Assessor:</strong> ${assessorName}</div>
      <div><strong>Date:</strong> ${dateStr}</div>
      <div><strong>Report Type:</strong> ${reportFormat.charAt(0).toUpperCase() + reportFormat.slice(1)} Assessment</div>
    </div>
    <div style="margin-top: 60px; font-size: 10pt; opacity: 0.7;">
      CONFIDENTIAL - For Authorized Recipients Only
    </div>
  </div>

  <!-- Table of Contents -->
  <div class="toc section">
    <h2 class="section-title">Table of Contents</h2>
    <div class="toc-item"><span>1. Executive Summary</span><span>3</span></div>
    <div class="toc-item"><span>2. Scope & Methodology</span><span>4</span></div>
    <div class="toc-item"><span>3. Findings Summary</span><span>5</span></div>
    <div class="toc-item"><span>4. Detailed Findings</span><span>6</span></div>
    ${actualFindings.map((f, i) => `<div class="toc-item" style="padding-left: 20px;"><span>4.${i+1}. ${f.title}</span><span>${6+i}</span></div>`).join('')}
    <div class="toc-item"><span>5. Recommendations</span><span>${6 + actualFindings.length}</span></div>
    <div class="toc-item"><span>6. Appendix</span><span>${7 + actualFindings.length}</span></div>
  </div>

  <!-- Executive Summary -->
  <div class="section" style="page-break-after: always;">
    <h2 class="section-title">1. Executive Summary</h2>
    <p style="margin-bottom: 20px;">${executiveSummary}</p>
    
    <h3 style="font-size: 14pt; margin: 24px 0 16px;">Risk Overview</h3>
    <div class="summary-grid">
      <div class="summary-card critical">
        <div class="summary-count">${severityCounts.critical}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="summary-count">${severityCounts.high}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-count">${severityCounts.medium}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="summary-count">${severityCounts.low}</div>
        <div class="summary-label">Low</div>
      </div>
    </div>
    
    <h3 style="font-size: 14pt; margin: 24px 0 16px;">Key Recommendations</h3>
    <ol style="padding-left: 20px;">
      ${severityCounts.critical > 0 ? '<li style="margin-bottom: 8px;"><strong>URGENT:</strong> Address all critical vulnerabilities within 24-48 hours</li>' : ''}
      ${severityCounts.high > 0 ? '<li style="margin-bottom: 8px;">Remediate high-severity issues within 7 days</li>' : ''}
      <li style="margin-bottom: 8px;">Implement security monitoring and alerting</li>
      <li style="margin-bottom: 8px;">Conduct regular security assessments</li>
      <li style="margin-bottom: 8px;">Establish a vulnerability management program</li>
    </ol>
  </div>

  <!-- Scope & Methodology -->
  <div class="section" style="page-break-after: always;">
    <h2 class="section-title">2. Scope & Methodology</h2>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Assessment Scope</h3>
    <table>
      <tr><th>Scope Item</th><th>Details</th></tr>
      <tr><td>Target</td><td>${data?.target || 'N/A'}</td></tr>
      <tr><td>Assessment Type</td><td>${reportFormat.charAt(0).toUpperCase() + reportFormat.slice(1)} Security Assessment</td></tr>
      <tr><td>Date</td><td>${dateStr}</td></tr>
      <tr><td>Total Findings</td><td>${actualFindings.length}</td></tr>
    </table>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Methodology</h3>
    <p>${data?.methodology || `The assessment was conducted using industry-standard methodologies including OWASP Testing Guide, PTES (Penetration Testing Execution Standard), and MITRE ATT&CK framework. Testing included both automated scanning and manual verification of findings.`}</p>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Standards & Frameworks</h3>
    <ul style="padding-left: 20px;">
      <li>OWASP Top 10 2021</li>
      <li>OWASP API Security Top 10</li>
      <li>CWE/SANS Top 25</li>
      <li>MITRE ATT&CK Framework</li>
      <li>NIST Cybersecurity Framework</li>
      <li>ISO 27001 Controls</li>
    </ul>
  </div>

  <!-- Findings Summary -->
  <div class="section" style="page-break-after: always;">
    <h2 class="section-title">3. Findings Summary</h2>
    
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Finding</th>
          <th>Severity</th>
          <th>Endpoint</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${actualFindings.map((f, i) => `
          <tr>
            <td>${i + 1}</td>
            <td>${f.title}</td>
            <td><span style="background: ${getSeverityColor(f.severity)}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10pt;">${f.severity.toUpperCase()}</span></td>
            <td style="font-family: monospace; font-size: 9pt;">${f.endpoint || 'N/A'}</td>
            <td>Open</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="findings-section section">
    <h2 class="section-title">4. Detailed Findings</h2>
    ${actualFindings.map((f, i) => renderFinding(f, i)).join('')}
  </div>

  <!-- Recommendations -->
  <div class="section" style="page-break-before: always;">
    <h2 class="section-title">5. Recommendations</h2>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Immediate Actions (Critical/High)</h3>
    <ul style="padding-left: 20px; margin-bottom: 20px;">
      ${actualFindings.filter(f => f.severity === 'critical' || f.severity === 'high').map(f => 
        `<li style="margin-bottom: 8px;">${f.remediation || `Address ${f.title}`}</li>`
      ).join('') || '<li>No immediate critical/high findings</li>'}
    </ul>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Short-term Actions (1-4 weeks)</h3>
    <ul style="padding-left: 20px; margin-bottom: 20px;">
      ${actualFindings.filter(f => f.severity === 'medium').map(f => 
        `<li style="margin-bottom: 8px;">${f.remediation || `Address ${f.title}`}</li>`
      ).join('') || '<li>No medium severity findings</li>'}
    </ul>
    
    <h3 style="font-size: 14pt; margin: 20px 0 12px;">Long-term Improvements</h3>
    <ul style="padding-left: 20px;">
      <li style="margin-bottom: 8px;">Implement a Security Development Lifecycle (SDL)</li>
      <li style="margin-bottom: 8px;">Conduct regular security training for developers</li>
      <li style="margin-bottom: 8px;">Deploy Web Application Firewall (WAF)</li>
      <li style="margin-bottom: 8px;">Implement continuous security monitoring</li>
      <li style="margin-bottom: 8px;">Establish regular penetration testing schedule</li>
    </ul>
  </div>

  <!-- Footer -->
  <div class="footer">
    <p><strong>OmniSec™ Enterprise VAPT Platform</strong></p>
    <p>This report is confidential and intended for the authorized recipient only.</p>
    <p>Generated: ${new Date().toISOString()} | Report ID: ${crypto.randomUUID().slice(0, 8)}</p>
    <p>© ${new Date().getFullYear()} OmniSec Security. All Rights Reserved.</p>
  </div>
</body>
</html>`;
  };

  const exportToPDF = async () => {
    setIsGenerating(true);
    
    try {
      const htmlContent = generatePDFContent();
      const printWindow = window.open('', '_blank');
      
      if (!printWindow) {
        toast({ 
          title: "Popup Blocked", 
          description: "Please allow popups to generate PDF reports", 
          variant: "destructive" 
        });
        setIsGenerating(false);
        return;
      }

      printWindow.document.write(htmlContent);
      printWindow.document.close();
      
      // Wait for content to load
      setTimeout(() => {
        printWindow.print();
        toast({ 
          title: "PDF Export Ready", 
          description: "Use 'Save as PDF' in the print dialog" 
        });
        setIsGenerating(false);
      }, 1000);
      
    } catch (error) {
      console.error('PDF generation error:', error);
      toast({ 
        title: "Export Failed", 
        description: "Failed to generate PDF report", 
        variant: "destructive" 
      });
      setIsGenerating(false);
    }
  };

  const downloadHTML = () => {
    const htmlContent = generatePDFContent();
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${reportTitle.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.html`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: "HTML Downloaded", description: "Open in browser and print to PDF" });
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-primary/20">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-lg">
          <FileText className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h2 className="text-xl font-bold">PDF Report Generator</h2>
          <p className="text-sm text-muted-foreground">Professional security assessment reports</p>
        </div>
      </div>

      {/* Report Configuration */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div>
          <label className="text-sm font-medium mb-2 block">Report Title</label>
          <Input
            value={reportTitle}
            onChange={(e) => setReportTitle(e.target.value)}
            placeholder="Security Assessment Report"
          />
        </div>
        <div>
          <label className="text-sm font-medium mb-2 block">Report Format</label>
          <Select value={reportFormat} onValueChange={(v: any) => setReportFormat(v)}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="detailed">Detailed (Technical)</SelectItem>
              <SelectItem value="executive">Executive Summary</SelectItem>
              <SelectItem value="technical">Technical Deep-Dive</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-sm font-medium mb-2 block">Client Name</label>
          <Input
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
            placeholder="Client Organization"
          />
        </div>
        <div>
          <label className="text-sm font-medium mb-2 block">Assessor</label>
          <Input
            value={assessorName}
            onChange={(e) => setAssessorName(e.target.value)}
            placeholder="Security Team"
          />
        </div>
      </div>

      {/* Findings Preview */}
      <div className="mb-6 p-4 bg-background/50 rounded-lg">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-medium">Report Preview</h3>
          <div className="flex gap-2">
            <Badge className="bg-red-500/20 text-red-400">{severityCounts.critical} Critical</Badge>
            <Badge className="bg-orange-500/20 text-orange-400">{severityCounts.high} High</Badge>
            <Badge className="bg-yellow-500/20 text-yellow-400">{severityCounts.medium} Medium</Badge>
            <Badge className="bg-blue-500/20 text-blue-400">{severityCounts.low} Low</Badge>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          {actualFindings.length} findings will be included in the report with full details, 
          remediation guidance, and executive summary.
        </p>
      </div>

      {/* Export Buttons */}
      <div className="flex gap-3">
        <Button onClick={exportToPDF} disabled={isGenerating} className="flex-1 gap-2">
          {isGenerating ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <FileDown className="h-4 w-4" />
          )}
          Export PDF
        </Button>
        <Button onClick={downloadHTML} variant="outline" className="flex-1 gap-2">
          <Download className="h-4 w-4" />
          Download HTML
        </Button>
        <Button onClick={() => window.print()} variant="outline" className="gap-2">
          <Printer className="h-4 w-4" />
          Print
        </Button>
      </div>
    </Card>
  );
};

export default PDFReportGenerator;
