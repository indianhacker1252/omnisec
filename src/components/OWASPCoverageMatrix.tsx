/**
 * OmniSec™ © HARSH MALIK
 * OWASPCoverageMatrix — shows which OWASP Top 10 categories were actually exercised
 * by the current scan (not just claimed). Derives from findings + scan phases.
 */
import { useMemo } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, Circle, ShieldAlert } from "lucide-react";

const OWASP_2021 = [
  { id: "A01", name: "Broken Access Control", keys: ["a01", "access control", "idor", "bola", "bopla", "auth_bypass", "privilege", "takeover", "open_redirect", "csrf", "directory_listing", "exposed", "unauthenticated", "oauth_open", "oauth_redirect"] },
  { id: "A02", name: "Cryptographic Failures", keys: ["a02", "crypto", "weak cipher", "tls", "ssl", "plaintext", "nossl", "no_ssl", "implicit_flow", "weak_jwt"] },
  { id: "A03", name: "Injection", keys: ["a03", "sqli", "sql_injection", "xss", "dom-xss", "dom_xss", "command", "rce", "xxe", "ssti", "ldap", "nosql", "injection", "header_injection", "crlf", "host_header", "traversal", "lfi", "rfi"] },
  { id: "A04", name: "Insecure Design", keys: ["a04", "design", "business_logic", "business logic", "race", "workflow", "logic_flaw"] },
  { id: "A05", name: "Security Misconfiguration", keys: ["a05", "misconfig", "cors", "header", "cookie", "directory listing", "default cred", "graphql_introspection", "field_suggestion", "discovery", "verbose_error", "debug"] },
  { id: "A06", name: "Vulnerable Components", keys: ["a06", "cve", "outdated", "vulnerable component", "dependency", "version"] },
  { id: "A07", name: "Auth & Identity Failures", keys: ["a07", "auth", "session", "jwt", "oauth", "credential", "weak_password", "no_pkce", "mfa", "brute"] },
  { id: "A08", name: "Software & Data Integrity", keys: ["a08", "deserialization", "integrity", "supply chain", "signed", "subresource"] },
  { id: "A09", name: "Security Logging & Monitoring", keys: ["a09", "logging", "monitoring", "audit"] },
  { id: "A10", name: "SSRF", keys: ["a10", "ssrf"] },
];

interface Props {
  findings: any[];
  phases?: string[];
}

export const OWASPCoverageMatrix = ({ findings, phases = [] }: Props) => {
  const coverage = useMemo(() => {
    const haystack = (
      findings
        .map((f) =>
          [f.title, f.category, f.owasp, f.finding_type, f.source_module, f.description]
            .filter(Boolean)
            .join(" ")
        )
        .join(" ") +
      " " +
      phases.join(" ")
    ).toLowerCase();

    return OWASP_2021.map((c) => {
      const hits = findings.filter((f) => {
        const hay = [f.title, f.category, f.owasp, f.finding_type, f.description]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return c.keys.some((k) => hay.includes(k));
      });
      const covered = c.keys.some((k) => haystack.includes(k));
      return { ...c, covered, count: hits.length };
    });
  }, [findings, phases]);

  const total = coverage.length;
  const exercised = coverage.filter((c) => c.covered).length;

  return (
    <Card className="p-4 border-primary/30">
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert className="h-4 w-4 text-primary" />
        <h3 className="font-semibold text-sm">OWASP Top 10 (2021) Coverage</h3>
        <Badge variant="outline" className="text-xs ml-auto">
          {exercised}/{total} exercised
        </Badge>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        {coverage.map((c) => (
          <div
            key={c.id}
            className={`p-2 rounded border text-xs ${
              c.covered
                ? "border-green-500/40 bg-green-500/5"
                : "border-border bg-muted/20 opacity-70"
            }`}
          >
            <div className="flex items-center gap-1 mb-1">
              {c.covered ? (
                <CheckCircle className="h-3 w-3 text-green-400" />
              ) : (
                <Circle className="h-3 w-3 text-muted-foreground" />
              )}
              <span className="font-mono text-[10px] font-bold">{c.id}</span>
              {c.count > 0 && (
                <Badge className="ml-auto text-[9px] h-4 px-1 bg-primary/20 text-primary border-primary/40">
                  {c.count}
                </Badge>
              )}
            </div>
            <div className="text-[10px] leading-tight">{c.name}</div>
          </div>
        ))}
      </div>
      <p className="text-[10px] text-muted-foreground mt-2">
        Coverage is derived from finding categories + executed scan phases. Empty cells mean that
        class was not exercised against this target — re-run with deeper modes to extend coverage.
      </p>
    </Card>
  );
};

export default OWASPCoverageMatrix;
