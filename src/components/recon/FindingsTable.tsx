import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Shield, RefreshCw, CheckCircle2, XCircle, Clock } from "lucide-react";
import { getFindings } from "@/services/ReconOrchestrator";
import { verifyFinding } from "@/services/VerificationEngine";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/50",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/50",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/50",
  info: "bg-muted text-muted-foreground border-border",
};

const verificationIcons: Record<string, JSX.Element> = {
  verified: <CheckCircle2 className="h-4 w-4 text-green-400" />,
  false_positive: <XCircle className="h-4 w-4 text-red-400" />,
  pending: <Clock className="h-4 w-4 text-yellow-400" />,
};

export const FindingsTable = () => {
  const { toast } = useToast();
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [verificationFilter, setVerificationFilter] = useState<string>("all");

  const refresh = async () => {
    setLoading(true);
    try {
      const filters: any = {};
      if (severityFilter !== "all") filters.severity = severityFilter;
      if (verificationFilter !== "all") filters.verification_status = verificationFilter;
      const data = await getFindings(filters);
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const channel = supabase
      .channel("recon-findings-changes")
      .on("postgres_changes", { event: "*", schema: "public", table: "recon_findings" }, () => refresh())
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [severityFilter, verificationFilter]);

  const handleVerify = async (finding: any) => {
    toast({ title: "Verifying...", description: finding.title });
    const result = await verifyFinding({
      id: finding.id,
      target_host: finding.target_host,
      url_path: finding.url_path,
      finding_type: finding.finding_type,
    });
    toast({
      title: result.verified ? "Verified ✓" : "False Positive",
      description: result.verified ? "Finding confirmed by secondary probe" : "Could not confirm — marked as false positive",
      variant: result.verified ? "default" : "destructive",
    });
    refresh();
  };

  // Group findings by hash for display
  const grouped = findings.reduce((acc: Record<string, any[]>, f) => {
    const key = `${f.target_host}|${f.finding_type}`;
    (acc[key] = acc[key] || []).push(f);
    return acc;
  }, {});

  return (
    <Card className="p-5 bg-card/50 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          Deduplicated Findings
        </h3>
        <div className="flex gap-2 items-center">
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-28 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="info">Info</SelectItem>
            </SelectContent>
          </Select>
          <Select value={verificationFilter} onValueChange={setVerificationFilter}>
            <SelectTrigger className="w-28 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="verified">Verified</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      <ScrollArea className="h-[500px]">
        {Object.keys(grouped).length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-muted-foreground">
            <Shield className="h-12 w-12 opacity-20 mb-2" />
            <p className="font-mono text-sm">No findings yet</p>
          </div>
        ) : (
          <div className="space-y-3">
            {Object.entries(grouped).map(([groupKey, groupFindings]) => (
              <div key={groupKey} className="border border-border/50 rounded-lg overflow-hidden">
                <div className="bg-muted/30 px-4 py-2 flex items-center justify-between">
                  <span className="font-mono text-sm font-semibold">{groupKey.split("|")[0]}</span>
                  <Badge variant="outline" className="text-xs">{groupKey.split("|")[1]} × {groupFindings.length}</Badge>
                </div>
                {groupFindings.map((f: any) => (
                  <div key={f.id} className="px-4 py-3 border-t border-border/30 flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge className={`text-xs ${severityColors[f.severity] || severityColors.info}`}>
                          {f.severity}
                        </Badge>
                        <div className="flex items-center gap-1">
                          {verificationIcons[f.verification_status] || verificationIcons.pending}
                          <span className="text-xs capitalize">{f.verification_status?.replace("_", " ")}</span>
                        </div>
                        {f.seen_count > 1 && (
                          <Badge variant="outline" className="text-xs">seen {f.seen_count}×</Badge>
                        )}
                      </div>
                      <p className="font-medium text-sm">{f.title}</p>
                      {f.description && <p className="text-xs text-muted-foreground mt-1 truncate">{f.description}</p>}
                      <div className="flex gap-3 mt-1 text-xs text-muted-foreground font-mono">
                        {f.url_path && <span>{f.url_path}</span>}
                        {f.vulnerable_parameter && <span>param: {f.vulnerable_parameter}</span>}
                        <span>hash: {f.hash_signature}</span>
                      </div>
                    </div>
                    {f.verification_status === "pending" && (
                      <Button variant="outline" size="sm" className="text-xs shrink-0" onClick={() => handleVerify(f)}>
                        Verify
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </ScrollArea>
    </Card>
  );
};
