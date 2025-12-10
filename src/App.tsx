import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Session } from "@supabase/supabase-js";
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
import AutonomousAttack from "./pages/AutonomousAttack";
import LLMRedTeam from "./pages/LLMRedTeam";
import LearningVaptAssistant from "./pages/LearningVaptAssistant";
import Settings from "./pages/Settings";
import Auth from "./pages/Auth";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setLoading(false);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });

    return () => subscription.unsubscribe();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-lg font-mono">Initializing...</div>
      </div>
    );
  }

  if (!session) {
    return <Navigate to="/auth" replace />;
  }

  return <>{children}</>;
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/auth" element={<Auth />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Index />
              </ProtectedRoute>
            }
          />
          <Route
            path="/recon"
            element={
              <ProtectedRoute>
                <ReconModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/vuln"
            element={
              <ProtectedRoute>
                <VulnModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/webapp"
            element={
              <ProtectedRoute>
                <WebAppModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/redteam"
            element={
              <ProtectedRoute>
                <RedTeamModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/blueteam"
            element={
              <ProtectedRoute>
                <BlueTeamModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/wireless"
            element={
              <ProtectedRoute>
                <WirelessModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/forensics"
            element={
              <ProtectedRoute>
                <ForensicsModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/reverse"
            element={
              <ProtectedRoute>
                <ReverseEngModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/aithreat"
            element={
              <ProtectedRoute>
                <AIThreatModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/ethics"
            element={
              <ProtectedRoute>
                <EthicsModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/malware-dev"
            element={
              <ProtectedRoute>
                <MalwareDevModule />
              </ProtectedRoute>
            }
          />
          <Route
            path="/kali"
            element={
              <ProtectedRoute>
                <KaliIntegration />
              </ProtectedRoute>
            }
          />
          <Route
            path="/autonomous"
            element={
              <ProtectedRoute>
                <AutonomousAttack />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />
          <Route
            path="/llm-redteam"
            element={
              <ProtectedRoute>
                <LLMRedTeam />
            </ProtectedRoute>
          }
          />
          <Route
            path="/vapt-learning"
            element={
              <ProtectedRoute>
                <LearningVaptAssistant />
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
