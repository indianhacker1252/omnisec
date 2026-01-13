import { CommandHeader } from "@/components/CommandHeader";
import { EnterpriseVAPTDashboard } from "@/components/EnterpriseVAPTDashboard";
import { SelfLearningEngine } from "@/components/SelfLearningEngine";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Brain, Target, TrendingUp } from "lucide-react";

const EnterpriseVAPTPage = () => {
  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      <main className="container mx-auto px-6 py-8">
        <Tabs defaultValue="vapt" className="space-y-6">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="vapt" className="gap-2">
              <Target className="h-4 w-4" />
              Enterprise VAPT
            </TabsTrigger>
            <TabsTrigger value="learning" className="gap-2">
              <Brain className="h-4 w-4" />
              AI Learning
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="vapt" className="space-y-6">
            <EnterpriseVAPTDashboard />
          </TabsContent>
          
          <TabsContent value="learning" className="space-y-6">
            <SelfLearningEngine />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default EnterpriseVAPTPage;
