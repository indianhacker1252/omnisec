/**
 * Subdomain Attack Surface Map Component
 * Visual table showing each subdomain with live status, tech stack, findings, and risk priority
 */
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Target,
  Network,
  Shield,
  ExternalLink
} from "lucide-react";

interface SubdomainEntry {
  subdomain: string;
  ip?: string;
  status: "live" | "dead" | "unknown";
  technologies: string[];
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  riskScore: number;
  findings: any[];
}

interface Props {
  subdomains: string[];
  findings: any[];
  onSelectSubdomain?: (subdomain: string) => void;
}

export const SubdomainAttackMap = ({ subdomains, findings, onSelectSubdomain }: Props) => {
  const [sortBy, setSortBy] = useState<"risk" | "findings" | "alpha">("risk");
  const [sortDir, setSortDir] = useState<"desc" | "asc">("desc");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  // Build subdomain entries from findings
  const subdomainMap = new Map<string, SubdomainEntry>();

  // Add discovered subdomains (even with 0 findings)
  for (const sub of subdomains) {
    subdomainMap.set(sub, {
      subdomain: sub,
      status: "live",
      technologies: [],
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      riskScore: 0,
      findings: []
    });
  }

  // Enrich with findings data
  for (const finding of findings) {
    if (!finding.endpoint) continue;
    try {
      const url = new URL(finding.endpoint.startsWith("http") ? finding.endpoint : `https://${finding.endpoint}`);
      const host = url.hostname;
      
      // Check if this host matches any subdomain
      const matchKey = subdomains.find(s => s === host || finding.endpoint.includes(s)) || host;
      
      if (!subdomainMap.has(matchKey)) {
        subdomainMap.set(matchKey, {
          subdomain: matchKey,
          status: "live",
          technologies: [],
          findingsCount: 0,
          criticalCount: 0,
          highCount: 0,
          riskScore: 0,
          findings: []
        });
      }
      
      const entry = subdomainMap.get(matchKey)!;
      entry.findingsCount++;
      entry.findings.push(finding);
      
      if (finding.severity === "critical") { entry.criticalCount++; entry.riskScore += 40; }
      else if (finding.severity === "high") { entry.highCount++; entry.riskScore += 20; }
      else if (finding.severity === "medium") entry.riskScore += 10;
      else if (finding.severity === "low") entry.riskScore += 3;
    } catch {}
  }

  let entries = Array.from(subdomainMap.values());

  // Sort
  entries.sort((a, b) => {
    let diff = 0;
    if (sortBy === "risk") diff = b.riskScore - a.riskScore;
    else if (sortBy === "findings") diff = b.findingsCount - a.findingsCount;
    else diff = a.subdomain.localeCompare(b.subdomain);
    return sortDir === "desc" ? diff : -diff;
  });

  const getRiskLabel = (score: number) => {
    if (score >= 60) return { label: "CRITICAL", cls: "bg-destructive/20 text-destructive border-destructive/50" };
    if (score >= 30) return { label: "HIGH", cls: "bg-orange-500/20 text-orange-400 border-orange-500/50" };
    if (score >= 10) return { label: "MEDIUM", cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50" };
    if (score > 0) return { label: "LOW", cls: "bg-blue-500/20 text-blue-400 border-blue-500/50" };
    return { label: "CLEAN", cls: "bg-green-500/20 text-green-400 border-green-500/50" };
  };

  const getStatusIcon = (status: string) => {
    if (status === "live") return <CheckCircle className="h-4 w-4 text-green-400" />;
    if (status === "dead") return <XCircle className="h-4 w-4 text-destructive" />;
    return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
  };

  const toggleSort = (field: "risk" | "findings" | "alpha") => {
    if (sortBy === field) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(field); setSortDir("desc"); }
  };

  const SortIcon = ({ field }: { field: string }) => (
    sortBy === field
      ? (sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />)
      : null
  );

  if (entries.length === 0) return null;

  return (
    <Card className="p-4 border-primary/20">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Network className="h-5 w-5 text-primary" />
          <h3 className="font-bold text-lg">Attack Surface Map</h3>
          <Badge variant="outline">{entries.length} targets</Badge>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>Sort by:</span>
          <Button variant="ghost" size="sm" className="h-7 px-2 gap-1" onClick={() => toggleSort("risk")}>
            Risk <SortIcon field="risk" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 gap-1" onClick={() => toggleSort("findings")}>
            Findings <SortIcon field="findings" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 gap-1" onClick={() => toggleSort("alpha")}>
            A–Z <SortIcon field="alpha" />
          </Button>
        </div>
      </div>

      {/* Risk summary bar */}
      <div className="grid grid-cols-4 gap-2 mb-4 text-center text-xs">
        {[
          { label: "Critical Targets", value: entries.filter(e => e.riskScore >= 60).length, cls: "text-destructive" },
          { label: "High Risk", value: entries.filter(e => e.riskScore >= 30 && e.riskScore < 60).length, cls: "text-orange-400" },
          { label: "Medium Risk", value: entries.filter(e => e.riskScore > 0 && e.riskScore < 30).length, cls: "text-yellow-400" },
          { label: "Clean", value: entries.filter(e => e.riskScore === 0).length, cls: "text-green-400" },
        ].map(s => (
          <div key={s.label} className="p-2 rounded bg-background/50 border border-border/30">
            <div className={`text-xl font-bold ${s.cls}`}>{s.value}</div>
            <div className="text-muted-foreground">{s.label}</div>
          </div>
        ))}
      </div>

      <ScrollArea className="h-80">
        <div className="space-y-1">
          {/* Header row */}
          <div className="grid grid-cols-12 gap-2 px-3 py-2 text-xs font-medium text-muted-foreground border-b border-border/30">
            <div className="col-span-1">Status</div>
            <div className="col-span-4">Subdomain</div>
            <div className="col-span-2">Risk</div>
            <div className="col-span-2 text-center">Findings</div>
            <div className="col-span-2 text-center">Crit/High</div>
            <div className="col-span-1"></div>
          </div>

          {entries.map((entry) => {
            const risk = getRiskLabel(entry.riskScore);
            const isExpanded = expandedRow === entry.subdomain;

            return (
              <div key={entry.subdomain}>
                <div
                  className={`grid grid-cols-12 gap-2 px-3 py-2 rounded-lg cursor-pointer transition-all hover:bg-primary/5 text-sm ${
                    isExpanded ? "bg-primary/10 border border-primary/30" : "border border-transparent"
                  }`}
                  onClick={() => setExpandedRow(isExpanded ? null : entry.subdomain)}
                >
                  <div className="col-span-1 flex items-center">
                    {getStatusIcon(entry.status)}
                  </div>
                  <div className="col-span-4 flex items-center gap-2 font-mono text-xs truncate">
                    <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                    <span className="truncate">{entry.subdomain}</span>
                  </div>
                  <div className="col-span-2 flex items-center">
                    <Badge className={`text-xs border ${risk.cls}`}>{risk.label}</Badge>
                  </div>
                  <div className="col-span-2 flex items-center justify-center">
                    <span className={`font-bold ${entry.findingsCount > 0 ? "text-primary" : "text-muted-foreground"}`}>
                      {entry.findingsCount}
                    </span>
                  </div>
                  <div className="col-span-2 flex items-center justify-center gap-1">
                    {entry.criticalCount > 0 && (
                      <span className="text-destructive font-bold text-xs">{entry.criticalCount}C</span>
                    )}
                    {entry.highCount > 0 && (
                      <span className="text-orange-400 font-bold text-xs">{entry.highCount}H</span>
                    )}
                    {entry.criticalCount === 0 && entry.highCount === 0 && (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </div>
                  <div className="col-span-1 flex items-center justify-end gap-1">
                    {onSelectSubdomain && (
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-6 w-6"
                        onClick={(e) => { e.stopPropagation(); onSelectSubdomain(entry.subdomain); }}
                        title="Filter findings for this subdomain"
                      >
                        <Target className="h-3 w-3" />
                      </Button>
                    )}
                    {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                  </div>
                </div>

                {/* Expanded row: show findings for this subdomain */}
                {isExpanded && entry.findings.length > 0 && (
                  <div className="mx-3 mb-2 p-3 bg-background/50 rounded border border-border/30 space-y-1">
                    <div className="text-xs font-medium text-muted-foreground mb-2">
                      Findings for {entry.subdomain}:
                    </div>
                    {entry.findings.slice(0, 8).map((f, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-border/20 last:border-0">
                        <Badge
                          className={`text-[10px] shrink-0 ${
                            f.severity === "critical" ? "bg-destructive/20 text-destructive border-destructive/40" :
                            f.severity === "high" ? "bg-orange-500/20 text-orange-400 border-orange-500/40" :
                            f.severity === "medium" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" :
                            "bg-blue-500/20 text-blue-400 border-blue-500/40"
                          }`}
                        >
                          {f.severity?.toUpperCase()}
                        </Badge>
                        <span className="flex-1 truncate">{f.title}</span>
                        {f.dualConfirmed && (
                          <span className="text-green-400 text-[10px] shrink-0">✓ Dual-Confirmed</span>
                        )}
                        <span className="text-muted-foreground shrink-0">{f.confidence}%</span>
                      </div>
                    ))}
                    {entry.findings.length > 8 && (
                      <div className="text-xs text-muted-foreground mt-1">
                        +{entry.findings.length - 8} more findings...
                      </div>
                    )}
                  </div>
                )}
                {isExpanded && entry.findings.length === 0 && (
                  <div className="mx-3 mb-2 p-3 bg-background/50 rounded border border-border/30 text-xs text-muted-foreground flex items-center gap-2">
                    <Shield className="h-4 w-4 text-green-400" />
                    No vulnerabilities found on this subdomain
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </Card>
  );
};
