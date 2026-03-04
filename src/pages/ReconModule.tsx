import { useState } from "react";
import { CommandHeader } from "@/components/CommandHeader";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Search, ArrowLeft, History, FileText } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useScanHistory } from "@/hooks/useScanHistory";
import { ReconScanPanel } from "@/components/recon/ReconScanPanel";
import { QueueManager } from "@/components/recon/QueueManager";
import { FindingsTable } from "@/components/recon/FindingsTable";

const ReconModule = () => {
  const navigate = useNavigate();
  const { getModuleHistory, getModuleReports } = useScanHistory();
  const [history, setHistory] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);

  const loadHistory = async () => {
    const [h, r] = await Promise.all([getModuleHistory("recon"), getModuleReports("recon")]);
    setHistory(h);
    setReports(r);
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
        <Button variant="ghost" onClick={() => navigate("/")} className="mb-6 gap-2">
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Search className="h-8 w-8 text-primary" />
            <h1 className="text-3xl font-bold font-mono">Reconnaissance Module</h1>
          </div>
          <p className="text-muted-foreground">
            Recursive subdomain enumeration, hash-based deduplication, and dual-probe verification
          </p>
        </div>

        <Tabs defaultValue="scan" className="space-y-4" onValueChange={(v) => v === "history" && loadHistory()}>
          <TabsList>
            <TabsTrigger value="scan">Pipeline</TabsTrigger>
            <TabsTrigger value="findings">Findings</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
          </TabsList>

          <TabsContent value="scan">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <ReconScanPanel />
              <div className="lg:col-span-2">
                <QueueManager />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="findings">
            <FindingsTable />
          </TabsContent>

          <TabsContent value="history">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <History className="h-5 w-5" />
                Scan History
              </h3>
              {history.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">No scan history yet</p>
              ) : (
                <ScrollArea className="h-96">
                  <div className="space-y-2">
                    {history.map((h) => (
                      <div key={h.id} className="flex items-center justify-between p-3 bg-background/50 rounded border border-border/50">
                        <div>
                          <p className="font-medium">{h.scan_type}</p>
                          <p className="text-xs text-muted-foreground">{h.target}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={h.status === "completed" ? "default" : "destructive"}>{h.status}</Badge>
                          <span className="text-xs text-muted-foreground">{h.findings_count || 0} findings</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="reports">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Saved Reports
              </h3>
              {reports.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">No reports saved yet</p>
              ) : (
                <ScrollArea className="h-96">
                  <div className="space-y-2">
                    {reports.map((r) => (
                      <div key={r.id} className="flex items-center justify-between p-3 bg-background/50 rounded border border-border/50">
                        <div>
                          <p className="font-medium">{r.title}</p>
                          <p className="text-xs text-muted-foreground">{r.summary}</p>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {new Date(r.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default ReconModule;
