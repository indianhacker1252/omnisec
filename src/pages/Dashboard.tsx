import { CommandHeader } from "@/components/CommandHeader";
import { ModuleCard } from "@/components/ModuleCard";
import { SystemStatus } from "@/components/SystemStatus";
import { AIAssistant } from "@/components/AIAssistant";
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
      status: "idle" as const,
      path: "/",
    },
    {
      title: "Vulnerability Intel",
      description: "CVE correlation and exploit database integration",
      icon: Bug,
      status: "active" as const,
      path: "/vuln",
    },
    {
      title: "Red Team Ops",
      description: "Metasploit, Empire sandbox for exploitation simulation",
      icon: Sword,
      status: "alert" as const,
      path: "/",
    },
    {
      title: "Blue Team Defense",
      description: "SIEM, MITRE ATT&CK mapping, and alert correlation",
      icon: ShieldCheck,
      status: "active" as const,
      path: "/",
    },
    {
      title: "Wireless Security",
      description: "WiFi, Bluetooth, NFC, and radio frequency analysis",
      icon: Wifi,
      status: "idle" as const,
      path: "/",
    },
    {
      title: "Forensics & IR",
      description: "Memory analysis, disk imaging, and incident response",
      icon: FileSearch,
      status: "idle" as const,
      path: "/",
    },
    {
      title: "Reverse Engineering",
      description: "Ghidra, radare2 integration for malware analysis",
      icon: Code,
      status: "idle" as const,
      path: "/",
    },
    {
      title: "AI Threat Engine",
      description: "ML-driven anomaly detection and predictive analysis",
      icon: Brain,
      status: "active" as const,
      path: "/",
    },
    {
      title: "Ethics & Governance",
      description: "Compliance auditing, audit logs, and responsible disclosure",
      icon: Scale,
      status: "active" as const,
      path: "/",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />

      <main className="container mx-auto px-6 py-8">
        {/* Top Section - System Status & AI Assistant */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-1">
            <SystemStatus />
          </div>
          <div className="lg:col-span-2 h-[400px]">
            <AIAssistant />
          </div>
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
