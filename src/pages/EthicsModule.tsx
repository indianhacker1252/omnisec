import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Scale, FileText, Shield, CheckCircle, Activity, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

const EthicsModule = () => {
  const navigate = useNavigate();
  const auditLogs = [
    {
      timestamp: new Date().toISOString(),
      user: "admin@omnisec.local",
      action: "Vulnerability Scan Initiated",
      target: "production-web-01",
      status: "Authorized",
    },
    {
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      user: "pentester@omnisec.local",
      action: "Exploitation Attempt",
      target: "test-db-server",
      status: "Authorized",
    },
    {
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      user: "analyst@omnisec.local",
      action: "Data Access",
      target: "customer_database",
      status: "Logged",
    },
  ];

  const compliance = [
    { standard: "ISO 27001", status: "compliant", coverage: 94 },
    { standard: "GDPR", status: "compliant", coverage: 98 },
    { standard: "SOC 2 Type II", status: "in-progress", coverage: 87 },
    { standard: "PCI DSS", status: "compliant", coverage: 91 },
    { standard: "HIPAA", status: "not-applicable", coverage: 0 },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Scale className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Ethics & Governance</h1>
          </div>
          <p className="text-muted-foreground">
            Compliance auditing, responsible disclosure, and ethical security practices
          </p>
        </div>

        <Tabs defaultValue="compliance" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="compliance">
              <Shield className="h-4 w-4 mr-2" />
              Compliance
            </TabsTrigger>
            <TabsTrigger value="audit">
              <FileText className="h-4 w-4 mr-2" />
              Audit Logs
            </TabsTrigger>
            <TabsTrigger value="disclosure">
              <Scale className="h-4 w-4 mr-2" />
              Responsible Disclosure
            </TabsTrigger>
          </TabsList>

          <TabsContent value="compliance">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Compliance Framework Status</h3>
              <div className="space-y-4">
                {compliance.map((item, idx) => (
                  <Card key={idx} className="p-4 bg-muted/50">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        {item.status === "compliant" ? (
                          <CheckCircle className="h-5 w-5 text-green-500" />
                        ) : item.status === "in-progress" ? (
                          <Activity className="h-5 w-5 text-yellow-500" />
                        ) : (
                          <div className="h-5 w-5" />
                        )}
                        <span className="font-semibold">{item.standard}</span>
                      </div>
                      <Badge
                        variant={
                          item.status === "compliant"
                            ? "default"
                            : item.status === "in-progress"
                            ? "secondary"
                            : "outline"
                        }
                      >
                        {item.status}
                      </Badge>
                    </div>
                    {item.coverage > 0 && (
                      <>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Coverage</span>
                          <span className="font-mono font-semibold">{item.coverage}%</span>
                        </div>
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              item.coverage >= 95
                                ? "bg-green-500"
                                : item.coverage >= 80
                                ? "bg-yellow-500"
                                : "bg-red-500"
                            }`}
                            style={{ width: `${item.coverage}%` }}
                          />
                        </div>
                      </>
                    )}
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="audit">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Security Audit Trail</h3>
                <Button variant="outline" size="sm">
                  <FileText className="mr-2 h-4 w-4" />
                  Export Logs
                </Button>
              </div>

              <div className="space-y-3">
                {auditLogs.map((log, idx) => (
                  <Card key={idx} className="p-4 border-l-4 border-cyber-cyan">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <div className="font-semibold text-sm mb-1">{log.action}</div>
                        <div className="text-xs text-muted-foreground">
                          User: <span className="font-mono">{log.user}</span>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Target: <span className="font-mono">{log.target}</span>
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge variant="outline">{log.status}</Badge>
                        <div className="text-xs text-muted-foreground mt-1">
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="disclosure">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Responsible Disclosure Program</h3>
              
              <div className="space-y-4">
                <Card className="p-4 bg-muted/50">
                  <h4 className="font-semibold mb-2">Disclosure Policy</h4>
                  <ul className="text-sm space-y-1 text-muted-foreground">
                    <li>• All discovered vulnerabilities must be reported through proper channels</li>
                    <li>• 90-day disclosure timeline after vendor notification</li>
                    <li>• Coordinated disclosure with affected parties</li>
                    <li>• Public recognition for ethical researchers</li>
                  </ul>
                </Card>

                <Card className="p-4 bg-muted/50">
                  <h4 className="font-semibold mb-2">Ethical Guidelines</h4>
                  <ul className="text-sm space-y-1 text-muted-foreground">
                    <li>• Always obtain written authorization before testing</li>
                    <li>• Respect scope limitations and rules of engagement</li>
                    <li>• Minimize impact on production systems</li>
                    <li>• Protect sensitive data discovered during assessments</li>
                    <li>• Comply with all applicable laws and regulations</li>
                  </ul>
                </Card>

                <Button className="w-full">
                  <FileText className="mr-2 h-4 w-4" />
                  Submit Vulnerability Report
                </Button>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default EthicsModule;
