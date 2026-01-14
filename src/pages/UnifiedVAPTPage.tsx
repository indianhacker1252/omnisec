import { CommandHeader } from "@/components/CommandHeader";
import { UnifiedVAPTDashboard } from "@/components/UnifiedVAPTDashboard";

const UnifiedVAPTPage = () => {
  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
        <UnifiedVAPTDashboard />
      </main>
    </div>
  );
};

export default UnifiedVAPTPage;
