/**
 * Finding Detail Modal — clickable full-detail view with POC, evidence, exploit code
 */
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import {
  X,
  Copy,
  Globe,
  Terminal,
  Bug,
  AlertTriangle,
  CheckCircle,
  ThumbsUp,
  ThumbsDown,
  Code,
  Shield,
  FileText,
  Layers,
  ExternalLink
} from "lucide-react";

interface Finding {
  id: string;
  severity: string;
  title: string;
  description: string;
  endpoint: string;
  subdomain?: string;
  method?: string;
  payload?: string;
  evidence?: string;
  evidence2?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  mitre?: string[];
  confidence: number;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
  dualConfirmed?: boolean;
  retryCount?: number;
}

interface Props {
  finding: Finding | null;
  onClose: () => void;
  onConfirm?: (f: Finding) => void;
  onFalsePositive?: (f: Finding) => void;
}

export const FindingDetailModal = ({ finding, onClose, onConfirm, onFalsePositive }: Props) => {
  const { toast } = useToast();

  if (!finding) return null;

  const copyText = (text: string, label = "Copied!") => {
    navigator.clipboard.writeText(text);
    toast({ title: label, description: "Copied to clipboard" });
  };

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case "critical": return "bg-destructive/20 text-destructive border-destructive/50";
      case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/50";
      case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
      case "low": return "bg-primary/20 text-primary border-primary/50";
      default: return "bg-muted text-muted-foreground border-border";
    }
  };

  const getCvssColor = (cvss?: number) => {
    if (!cvss) return "text-muted-foreground";
    if (cvss >= 9) return "text-destructive";
    if (cvss >= 7) return "text-orange-400";
    if (cvss >= 4) return "text-yellow-400";
    return "text-primary";
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" />
      <Card
        className="relative z-10 w-full max-w-3xl max-h-[90vh] flex flex-col border-primary/30 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-border flex items-start justify-between gap-4">
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge className={`border ${getSeverityStyle(finding.severity)}`}>
                {finding.severity.toUpperCase()}
              </Badge>
              {finding.dualConfirmed && (
                <Badge variant="outline" className="border-green-500/50 text-green-400 text-xs gap-1">
                  <CheckCircle className="h-3 w-3" /> Dual-Confirmed
                </Badge>
              )}
              <Badge variant="outline" className="text-xs">
                {finding.confidence}% confidence
              </Badge>
              {finding.cwe && (
                <Badge variant="outline" className="text-xs font-mono">{finding.cwe}</Badge>
              )}
              {finding.cvss && (
                <Badge variant="outline" className={`text-xs font-mono ${getCvssColor(finding.cvss)}`}>
                  CVSS {finding.cvss}
                </Badge>
              )}
            </div>
            <h2 className="text-lg font-bold leading-tight">{finding.title}</h2>
            <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
              <Globe className="h-3 w-3 shrink-0" />
              <span className="truncate">{finding.endpoint}</span>
              {finding.method && (
                <Badge variant="outline" className="text-[10px] shrink-0">{finding.method}</Badge>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {onConfirm && (
              <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => onConfirm(finding)} title="Confirm vulnerability">
                <ThumbsUp className="h-4 w-4 text-green-400" />
              </Button>
            )}
            {onFalsePositive && (
              <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => onFalsePositive(finding)} title="Mark as false positive">
                <ThumbsDown className="h-4 w-4 text-destructive" />
              </Button>
            )}
            <Button size="icon" variant="ghost" className="h-8 w-8" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <ScrollArea className="flex-1">
          <div className="p-5 space-y-5">
            {/* Description */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <FileText className="h-4 w-4 text-muted-foreground" />
                <h3 className="font-semibold text-sm">Description</h3>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
            </section>

            {/* Evidence — dual confirmation breakdown */}
            {(finding.evidence || finding.evidence2) && (
              <section>
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" />
                  <h3 className="font-semibold text-sm">Evidence</h3>
                </div>
                <div className="space-y-2">
                  {finding.evidence && (
                    <div className="p-3 bg-muted/50 rounded border border-border/50">
                      <div className="text-xs font-medium text-muted-foreground mb-1">
                        Method 1 (Primary Detection)
                      </div>
                      <p className="text-sm font-mono break-all">{finding.evidence}</p>
                    </div>
                  )}
                  {finding.evidence2 && (
                    <div className="p-3 bg-green-500/5 rounded border border-green-500/30">
                      <div className="text-xs font-medium text-green-400 mb-1 flex items-center gap-1">
                        <CheckCircle className="h-3 w-3" /> Method 2 (Independent Verification)
                      </div>
                      <p className="text-sm font-mono break-all">{finding.evidence2}</p>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* Payload used */}
            {finding.payload && (
              <section>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Bug className="h-4 w-4 text-muted-foreground" />
                    <h3 className="font-semibold text-sm">Attack Payload</h3>
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 text-xs gap-1" onClick={() => copyText(finding.payload!)}>
                    <Copy className="h-3 w-3" /> Copy
                  </Button>
                </div>
                <code className="block text-xs bg-muted p-3 rounded font-mono break-all border border-border/50">
                  {finding.payload}
                </code>
              </section>
            )}

            {/* POC Command */}
            {finding.poc && (
              <section>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-primary" />
                    <h3 className="font-semibold text-sm">Proof of Concept (POC)</h3>
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 text-xs gap-1" onClick={() => copyText(finding.poc!, "POC Copied!")}>
                    <Copy className="h-3 w-3" /> Copy POC
                  </Button>
                </div>
                <pre className="text-xs bg-background border border-primary/20 p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed text-primary/90">
                  {finding.poc}
                </pre>
              </section>
            )}

            {/* Exploit Code */}
            {finding.exploitCode && (
              <section>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Code className="h-4 w-4 text-orange-400" />
                    <h3 className="font-semibold text-sm">Exploit Code</h3>
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 text-xs gap-1" onClick={() => copyText(finding.exploitCode!, "Exploit Copied!")}>
                    <Copy className="h-3 w-3" /> Copy Code
                  </Button>
                </div>
                <pre className="text-xs bg-background border border-orange-500/20 p-3 rounded font-mono overflow-x-auto max-h-52 text-orange-300/90 leading-relaxed">
                  {finding.exploitCode}
                </pre>
              </section>
            )}

            {/* Remediation */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-green-400" />
                <h3 className="font-semibold text-sm">Remediation</h3>
              </div>
              <div className="p-3 bg-green-500/5 rounded border border-green-500/20">
                <p className="text-sm text-muted-foreground leading-relaxed">{finding.remediation}</p>
              </div>
            </section>

            {/* MITRE ATT&CK */}
            {finding.mitre && finding.mitre.length > 0 && (
              <section>
                <div className="flex items-center gap-2 mb-2">
                  <Layers className="h-4 w-4 text-muted-foreground" />
                  <h3 className="font-semibold text-sm">MITRE ATT&CK</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {finding.mitre.map((id) => (
                    <a
                      key={id}
                      href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1"
                    >
                      <Badge variant="outline" className="font-mono text-xs hover:border-primary/50 cursor-pointer gap-1">
                        {id} <ExternalLink className="h-2.5 w-2.5" />
                      </Badge>
                    </a>
                  ))}
                </div>
              </section>
            )}

            {/* Response snippet */}
            {finding.response && (
              <section>
                <div className="flex items-center gap-2 mb-2">
                  <Terminal className="h-4 w-4 text-muted-foreground" />
                  <h3 className="font-semibold text-sm">Server Response Snippet</h3>
                </div>
                <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto max-h-32 text-muted-foreground">
                  {finding.response}
                </pre>
              </section>
            )}
          </div>
        </ScrollArea>
      </Card>
    </div>
  );
};
