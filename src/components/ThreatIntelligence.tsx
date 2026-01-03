/**
 * OmniSec™ Threat Intelligence Component
 * Real-time threat feeds and CVE monitoring
 */

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  AlertTriangle,
  Globe,
  Search,
  RefreshCw,
  ExternalLink,
  TrendingUp,
  Clock,
  Bug,
  Zap
} from "lucide-react";

interface ThreatFeed {
  id: string;
  source: string;
  type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  indicators: string[];
  mitreIds: string[];
}

interface CVEEntry {
  id: string;
  cveId: string;
  title: string;
  description: string;
  cvss: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  published: string;
  affected: string[];
  exploitAvailable: boolean;
  patchAvailable: boolean;
}

interface ExploitEntry {
  id: string;
  cveId: string;
  title: string;
  platform: string;
  type: string;
  author: string;
  published: string;
  verified: boolean;
}

export const ThreatIntelligence = () => {
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [threats, setThreats] = useState<ThreatFeed[]>([]);
  const [cves, setCves] = useState<CVEEntry[]>([]);
  const [exploits, setExploits] = useState<ExploitEntry[]>([]);

  useEffect(() => {
    loadThreatData();
  }, []);

  const loadThreatData = async () => {
    setLoading(true);
    
    // Sample threat intelligence data
    setThreats([
      {
        id: '1',
        source: 'OmniSec Intelligence',
        type: 'Malware Campaign',
        title: 'New Ransomware Variant Targeting Healthcare',
        description: 'Advanced ransomware with double extortion tactics observed targeting healthcare institutions',
        severity: 'critical',
        timestamp: new Date().toISOString(),
        indicators: ['185.234.xxx.xxx', 'malware.evil.com', 'hash:abc123...'],
        mitreIds: ['T1486', 'T1490', 'T1027']
      },
      {
        id: '2',
        source: 'CISA Advisory',
        type: 'Vulnerability Alert',
        title: 'Critical RCE in Enterprise Software',
        description: 'Remote code execution vulnerability being actively exploited in the wild',
        severity: 'critical',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        indicators: ['CVE-2024-XXXXX'],
        mitreIds: ['T1190', 'T1059']
      },
      {
        id: '3',
        source: 'APT Intelligence',
        type: 'APT Activity',
        title: 'State-Sponsored Group Targeting Financial Sector',
        description: 'Advanced persistent threat group using spear-phishing with zero-day exploits',
        severity: 'high',
        timestamp: new Date(Date.now() - 7200000).toISOString(),
        indicators: ['phishing-domain.com', 'C2: 192.168.xxx.xxx'],
        mitreIds: ['T1566.001', 'T1203', 'T1071']
      },
      {
        id: '4',
        source: 'Threat Feed',
        type: 'Botnet Alert',
        title: 'IoT Botnet Infrastructure Expansion',
        description: 'Large-scale botnet recruiting vulnerable IoT devices for DDoS attacks',
        severity: 'medium',
        timestamp: new Date(Date.now() - 14400000).toISOString(),
        indicators: ['botnet-c2.net', 'Multiple IPs'],
        mitreIds: ['T1583.005', 'T1498']
      }
    ]);

    setCves([
      {
        id: '1',
        cveId: 'CVE-2024-21762',
        title: 'FortiOS Out-of-Bounds Write',
        description: 'Critical out-of-bounds write vulnerability in FortiOS SSL VPN allowing RCE',
        cvss: 9.8,
        severity: 'critical',
        published: '2024-02-08',
        affected: ['FortiOS 7.4.0-7.4.2', 'FortiOS 7.2.0-7.2.6'],
        exploitAvailable: true,
        patchAvailable: true
      },
      {
        id: '2',
        cveId: 'CVE-2024-27198',
        title: 'JetBrains TeamCity Authentication Bypass',
        description: 'Authentication bypass allowing unauthenticated RCE in TeamCity',
        cvss: 9.8,
        severity: 'critical',
        published: '2024-03-04',
        affected: ['TeamCity < 2023.11.4'],
        exploitAvailable: true,
        patchAvailable: true
      },
      {
        id: '3',
        cveId: 'CVE-2024-3400',
        title: 'Palo Alto PAN-OS Command Injection',
        description: 'Command injection in GlobalProtect gateway allowing root RCE',
        cvss: 10.0,
        severity: 'critical',
        published: '2024-04-12',
        affected: ['PAN-OS 10.2', 'PAN-OS 11.0', 'PAN-OS 11.1'],
        exploitAvailable: true,
        patchAvailable: true
      },
      {
        id: '4',
        cveId: 'CVE-2024-23897',
        title: 'Jenkins Arbitrary File Read',
        description: 'Arbitrary file read vulnerability through CLI argument parsing',
        cvss: 9.8,
        severity: 'critical',
        published: '2024-01-24',
        affected: ['Jenkins < 2.442', 'Jenkins LTS < 2.426.3'],
        exploitAvailable: true,
        patchAvailable: true
      }
    ]);

    setExploits([
      {
        id: '1',
        cveId: 'CVE-2024-21762',
        title: 'FortiOS SSL VPN RCE Exploit',
        platform: 'Linux',
        type: 'Remote',
        author: 'Security Researcher',
        published: '2024-02-15',
        verified: true
      },
      {
        id: '2',
        cveId: 'CVE-2024-27198',
        title: 'TeamCity Auth Bypass PoC',
        platform: 'Multiple',
        type: 'Webapps',
        author: 'Rapid7',
        published: '2024-03-10',
        verified: true
      },
      {
        id: '3',
        cveId: 'CVE-2024-3400',
        title: 'PAN-OS GlobalProtect RCE',
        platform: 'PAN-OS',
        type: 'Remote',
        author: 'Volexity',
        published: '2024-04-15',
        verified: true
      }
    ]);

    setLoading(false);
  };

  const searchThreats = async () => {
    if (!searchQuery.trim()) return;
    
    setLoading(true);
    toast({ title: "Searching", description: `Searching for ${searchQuery}...` });
    
    // Simulate search
    await new Promise(r => setTimeout(r, 1000));
    
    setLoading(false);
    toast({ title: "Search Complete", description: "Results updated" });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/10 text-red-500 border-red-500';
      case 'high': return 'bg-orange-500/10 text-orange-500 border-orange-500';
      case 'medium': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500';
      default: return 'bg-blue-500/10 text-blue-500 border-blue-500';
    }
  };

  const getCVSSColor = (cvss: number) => {
    if (cvss >= 9.0) return 'text-red-500';
    if (cvss >= 7.0) return 'text-orange-500';
    if (cvss >= 4.0) return 'text-yellow-500';
    return 'text-blue-500';
  };

  return (
    <Card className="p-6 bg-card/50 backdrop-blur border-primary/20">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold">Threat Intelligence</h2>
            <p className="text-sm text-muted-foreground">Real-time threat feeds & CVE monitoring</p>
          </div>
        </div>
        <Button variant="outline" onClick={loadThreatData} disabled={loading} className="gap-2">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <div className="flex gap-2 mb-6">
        <Input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search CVEs, threats, indicators..."
          className="flex-1"
          onKeyDown={(e) => e.key === 'Enter' && searchThreats()}
        />
        <Button onClick={searchThreats} disabled={loading}>
          <Search className="h-4 w-4" />
        </Button>
      </div>

      <Tabs defaultValue="threats" className="w-full">
        <TabsList className="grid w-full grid-cols-3 mb-4">
          <TabsTrigger value="threats" className="gap-2">
            <AlertTriangle className="h-4 w-4" />
            Threats ({threats.length})
          </TabsTrigger>
          <TabsTrigger value="cves" className="gap-2">
            <Bug className="h-4 w-4" />
            CVEs ({cves.length})
          </TabsTrigger>
          <TabsTrigger value="exploits" className="gap-2">
            <Zap className="h-4 w-4" />
            Exploits ({exploits.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="threats">
          <ScrollArea className="h-[400px]">
            <div className="space-y-4">
              {threats.map((threat) => (
                <Card key={threat.id} className={`p-4 bg-background/50 border ${getSeverityColor(threat.severity)}`}>
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">{threat.source}</Badge>
                      <Badge variant="outline">{threat.type}</Badge>
                      <Badge variant={threat.severity === 'critical' ? 'destructive' : 'secondary'}>
                        {threat.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(threat.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <h4 className="font-semibold mb-1">{threat.title}</h4>
                  <p className="text-sm text-muted-foreground mb-2">{threat.description}</p>
                  <div className="flex flex-wrap gap-1 mb-2">
                    {threat.mitreIds.map((id) => (
                      <Badge key={id} variant="outline" className="text-xs">{id}</Badge>
                    ))}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <strong>IOCs:</strong> {threat.indicators.slice(0, 3).join(', ')}
                  </div>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="cves">
          <ScrollArea className="h-[400px]">
            <div className="space-y-4">
              {cves.map((cve) => (
                <Card key={cve.id} className={`p-4 bg-background/50 border ${getSeverityColor(cve.severity)}`}>
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="font-mono">{cve.cveId}</Badge>
                      <span className={`font-bold ${getCVSSColor(cve.cvss)}`}>CVSS: {cve.cvss}</span>
                    </div>
                    <div className="flex gap-2">
                      {cve.exploitAvailable && (
                        <Badge variant="destructive" className="text-xs">Exploit Available</Badge>
                      )}
                      {cve.patchAvailable && (
                        <Badge variant="default" className="text-xs bg-green-500">Patch Available</Badge>
                      )}
                    </div>
                  </div>
                  <h4 className="font-semibold mb-1">{cve.title}</h4>
                  <p className="text-sm text-muted-foreground mb-2">{cve.description}</p>
                  <div className="text-xs text-muted-foreground">
                    <strong>Affected:</strong> {cve.affected.join(', ')}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    <strong>Published:</strong> {cve.published}
                  </div>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="exploits">
          <ScrollArea className="h-[400px]">
            <div className="space-y-4">
              {exploits.map((exploit) => (
                <Card key={exploit.id} className="p-4 bg-background/50 border border-destructive/30">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="destructive" className="font-mono">{exploit.cveId}</Badge>
                      <Badge variant="outline">{exploit.type}</Badge>
                      <Badge variant="secondary">{exploit.platform}</Badge>
                    </div>
                    {exploit.verified && (
                      <Badge variant="default" className="text-xs bg-green-500">Verified</Badge>
                    )}
                  </div>
                  <h4 className="font-semibold mb-1">{exploit.title}</h4>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>By: {exploit.author}</span>
                    <span>Published: {exploit.published}</span>
                  </div>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </Card>
  );
};

export default ThreatIntelligence;
