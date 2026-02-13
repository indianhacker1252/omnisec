import { CommandHeader } from "@/components/CommandHeader";
import { ModuleCard } from "@/components/ModuleCard";
import { SystemStatus } from "@/components/SystemStatus";
import { AIAssistant } from "@/components/AIAssistant";
import { VoiceAssistant } from "@/components/VoiceAssistant";
import { PerformanceDashboard } from "@/components/PerformanceDashboard";
import { ScanProgressDashboard } from "@/components/ScanProgressDashboard";
import { AutomatedWorkflow } from "@/components/AutomatedWorkflow";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import {
  Search,
  Globe,
  Bug,
  Sword,
  ShieldCheck,
  Wifi,
  FileSearch,
  Code,
  Brain,
  Scale,
  Terminal,
  Skull,
  Zap,
  Bot,
  Cloud,
  Key,
  Network,
  Target,
  Layers,
  TrendingUp,
  Eye,
  FileText,
  ClipboardCheck,
} from "lucide-react";

const Dashboard = () => {
  const navigate = useNavigate();
  const { toast } = useToast();

  const modules = [
    {
      title: "Reconnaissance",
      description: "Network mapping, asset discovery, and OSINT gathering",
      icon: Search,
      status: "active" as const,
      path: "/recon",
    },
    {
      title: "Web & App Analysis",
      description: "Burp Suite, ZAP integration for vulnerability scanning",
      icon: Globe,
      status: "active" as const,
      path: "/webapp",
    },
    {
      title: "Vulnerability Intel",
      description: "CVE correlation and exploit database integration",
      icon: Bug,
      status: "active" as const,
      path: "/vuln",
    },
    {
      title: "API Security",
      description: "REST, GraphQL, gRPC testing with OWASP API Top 10",
      icon: Network,
      status: "active" as const,
      path: "/api-security",
    },
    {
      title: "Cloud Security",
      description: "AWS, Azure, GCP misconfiguration and vulnerability testing",
      icon: Cloud,
      status: "active" as const,
      path: "/cloud-security",
    },
    {
      title: "IAM & Identity",
      description: "OAuth, SAML, SSO, JWT, and MFA security testing",
      icon: Key,
      status: "active" as const,
      path: "/iam-security",
    },
    {
      title: "Red Team Ops",
      description: "Metasploit, Empire sandbox for exploitation simulation",
      icon: Sword,
      status: "active" as const,
      path: "/redteam",
    },
    {
      title: "Blue Team Defense",
      description: "SIEM, MITRE ATT&CK mapping, and alert correlation",
      icon: ShieldCheck,
      status: "active" as const,
      path: "/blueteam",
    },
    {
      title: "Wireless Security",
      description: "WiFi, Bluetooth, NFC, and radio frequency analysis",
      icon: Wifi,
      status: "active" as const,
      path: "/wireless",
    },
    {
      title: "Forensics & IR",
      description: "Memory analysis, disk imaging, and incident response",
      icon: FileSearch,
      status: "active" as const,
      path: "/forensics",
    },
    {
      title: "Reverse Engineering",
      description: "Ghidra, radare2 integration for malware analysis",
      icon: Code,
      status: "idle" as const,
      path: "/reverse",
    },
    {
      title: "AI Threat Engine",
      description: "ML-driven anomaly detection and predictive analysis",
      icon: Brain,
      status: "active" as const,
      path: "/aithreat",
    },
    {
      title: "LLM Red Teaming",
      description: "DeepTeam-inspired AI security vulnerability testing",
      icon: Bot,
      status: "active" as const,
      path: "/llm-redteam",
    },
    {
      title: "Ethics & Governance",
      description: "Compliance auditing, audit logs, and responsible disclosure",
      icon: Scale,
      status: "active" as const,
      path: "/ethics",
    },
    {
      title: "Malware Development",
      description: "Educational malware creation and reverse engineering",
      icon: Skull,
      status: "idle" as const,
      path: "/malware-dev",
    },
    {
      title: "Kali Integration",
      description: "Remote SSH connection and tool execution",
      icon: Terminal,
      status: "idle" as const,
      path: "/kali",
    },
    {
      title: "Autonomous VAPT (XBOW-like)",
      description: "AI-powered autonomous VAPT with endpoint discovery, exploit generation & self-learning",
      icon: Zap,
      status: "active" as const,
      path: "/unified-vapt",
    },
    {
      title: "Scope Validator",
      description: "Enterprise authorization & engagement scope configuration",
      icon: ClipboardCheck,
      status: "active" as const,
      path: "/scope-validator",
    },
    {
      title: "PDF Reports",
      description: "Generate professional PDF security assessment reports",
      icon: FileText,
      status: "active" as const,
      path: "/pdf-reports",
    },
    {
      title: "Security Reports",
      description: "Centralized view of all scan reports and findings",
      icon: Eye,
      status: "active" as const,
      path: "/reports",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />

      <main className="container mx-auto px-6 py-8">
        {/* Top Section - Voice & AI Assistant + System Status */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-1 space-y-6">
            <VoiceAssistant />
            <SystemStatus />
          </div>
          <div className="lg:col-span-2 h-[500px]">
            <AIAssistant />
          </div>
        </div>

        {/* Scan Progress & Automated Workflow */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <ScanProgressDashboard />
          <AutomatedWorkflow />
        </div>

        {/* Performance Dashboard */}
        <div className="mb-8">
          <PerformanceDashboard />
        </div>

        {/* Modules Grid */}
        <div className="mb-6">
          <h2 className="text-2xl font-bold font-mono mb-2">
            Security Modules
          </h2>
          <p className="text-muted-foreground text-sm mb-6">
            Unified control center for all cybersecurity operations
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {modules.map((module) => (
            <ModuleCard
              key={module.title}
              title={module.title}
              description={module.description}
              icon={module.icon}
              status={module.status}
              onClick={() =>
                module.path !== "/"
                  ? navigate(module.path)
                  : toast({
                      title: "Module coming soon",
                      description: "This module will be enabled shortly.",
                    })
              }
            />
          ))}
        </div>

        {/* Footer Info */}
        <div className="mt-12 pt-6 border-t border-border/50">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <p className="font-mono">
              OmniSec v1.0.0 | All systems operational | Lab Mode: Active
            </p>
            <p className="font-mono">
              Compliance: ISO27001 • GDPR • Responsible Disclosure Enabled
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
