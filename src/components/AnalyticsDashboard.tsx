import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  AreaChart,
  Area
} from "recharts";
import { 
  BarChart3, 
  PieChart as PieIcon, 
  TrendingUp,
  Target,
  Shield,
  AlertTriangle
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'];

export const AnalyticsDashboard = () => {
  const [severityData, setSeverityData] = useState<{ name: string; value: number }[]>([]);
  const [moduleData, setModuleData] = useState<{ module: string; scans: number; findings: number }[]>([]);
  const [trendData, setTrendData] = useState<{ date: string; scans: number; findings: number }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const fetchAnalytics = async () => {
    try {
      // Fetch scan history for analytics
      const { data: scans } = await supabase
        .from('scan_history')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      // Fetch alerts for severity distribution
      const { data: alerts } = await supabase
        .from('security_alerts')
        .select('severity')
        .order('created_at', { ascending: false })
        .limit(100);

      if (alerts && alerts.length > 0) {
        const severityCounts: Record<string, number> = {};
        alerts.forEach(a => {
          severityCounts[a.severity] = (severityCounts[a.severity] || 0) + 1;
        });
        setSeverityData(Object.entries(severityCounts).map(([name, value]) => ({ name, value })));
      } else {
        setSeverityData([
          { name: 'Critical', value: 12 },
          { name: 'High', value: 28 },
          { name: 'Medium', value: 45 },
          { name: 'Low', value: 67 },
          { name: 'Info', value: 23 },
        ]);
      }

      if (scans && scans.length > 0) {
        // Group by module
        const moduleStats: Record<string, { scans: number; findings: number }> = {};
        scans.forEach(s => {
          if (!moduleStats[s.module]) {
            moduleStats[s.module] = { scans: 0, findings: 0 };
          }
          moduleStats[s.module].scans++;
          moduleStats[s.module].findings += s.findings_count || 0;
        });
        setModuleData(Object.entries(moduleStats).map(([module, stats]) => ({
          module,
          scans: stats.scans,
          findings: stats.findings
        })));

        // Create trend data (last 7 days)
        const now = new Date();
        const trends: { date: string; scans: number; findings: number }[] = [];
        for (let i = 6; i >= 0; i--) {
          const date = new Date(now);
          date.setDate(date.getDate() - i);
          const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          const dayScans = scans.filter(s => {
            const scanDate = new Date(s.created_at);
            return scanDate.toDateString() === date.toDateString();
          });
          trends.push({
            date: dateStr,
            scans: dayScans.length,
            findings: dayScans.reduce((sum, s) => sum + (s.findings_count || 0), 0)
          });
        }
        setTrendData(trends);
      } else {
        // Demo data
        setModuleData([
          { module: 'Web App', scans: 45, findings: 78 },
          { module: 'Recon', scans: 32, findings: 12 },
          { module: 'API', scans: 28, findings: 34 },
          { module: 'Cloud', scans: 15, findings: 23 },
          { module: 'IAM', scans: 12, findings: 8 },
        ]);
        setTrendData([
          { date: 'Mon', scans: 12, findings: 8 },
          { date: 'Tue', scans: 19, findings: 14 },
          { date: 'Wed', scans: 8, findings: 5 },
          { date: 'Thu', scans: 25, findings: 22 },
          { date: 'Fri', scans: 31, findings: 28 },
          { date: 'Sat', scans: 15, findings: 11 },
          { date: 'Sun', scans: 22, findings: 18 },
        ]);
      }
    } catch (error) {
      console.error('Error fetching analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-cyber-purple" />
          Advanced Analytics
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="overview">
          <TabsList className="w-full mb-4">
            <TabsTrigger value="overview" className="flex-1">Overview</TabsTrigger>
            <TabsTrigger value="severity" className="flex-1">Severity</TabsTrigger>
            <TabsTrigger value="trends" className="flex-1">Trends</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={moduleData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="module" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px'
                    }}
                  />
                  <Bar dataKey="scans" fill="hsl(var(--cyber-cyan))" name="Scans" />
                  <Bar dataKey="findings" fill="hsl(var(--cyber-purple))" name="Findings" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </TabsContent>

          <TabsContent value="severity">
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </TabsContent>

          <TabsContent value="trends">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px'
                    }}
                  />
                  <Area type="monotone" dataKey="scans" stackId="1" stroke="hsl(var(--cyber-cyan))" fill="hsl(var(--cyber-cyan))" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="findings" stackId="2" stroke="hsl(var(--cyber-purple))" fill="hsl(var(--cyber-purple))" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
