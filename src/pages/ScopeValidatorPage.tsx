import { CommandHeader } from "@/components/CommandHeader";
import { ScopeValidator } from "@/components/ScopeValidator";

const ScopeValidatorPage = () => {
  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
        <ScopeValidator />
      </main>
    </div>
  );
};

export default ScopeValidatorPage;
