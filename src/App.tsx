import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import ReconModule from "./pages/ReconModule";
import VulnModule from "./pages/VulnModule";
import WebAppModule from "./pages/WebAppModule";
import RedTeamModule from "./pages/RedTeamModule";
import BlueTeamModule from "./pages/BlueTeamModule";
import WirelessModule from "./pages/WirelessModule";
import ForensicsModule from "./pages/ForensicsModule";
import ReverseEngModule from "./pages/ReverseEngModule";
import AIThreatModule from "./pages/AIThreatModule";
import EthicsModule from "./pages/EthicsModule";
import MalwareDevModule from "./pages/MalwareDevModule";
import KaliIntegration from "./pages/KaliIntegration";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/recon" element={<ReconModule />} />
          <Route path="/vuln" element={<VulnModule />} />
          <Route path="/webapp" element={<WebAppModule />} />
          <Route path="/redteam" element={<RedTeamModule />} />
          <Route path="/blueteam" element={<BlueTeamModule />} />
          <Route path="/wireless" element={<WirelessModule />} />
          <Route path="/forensics" element={<ForensicsModule />} />
          <Route path="/reverse" element={<ReverseEngModule />} />
          <Route path="/aithreat" element={<AIThreatModule />} />
          <Route path="/ethics" element={<EthicsModule />} />
          <Route path="/malware-dev" element={<MalwareDevModule />} />
          <Route path="/kali" element={<KaliIntegration />} />
          <Route path="/settings" element={<Settings />} />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
