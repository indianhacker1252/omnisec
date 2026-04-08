/**
 * BackgroundScanIndicator — floating indicator showing active background scan
 * Rendered globally so it's visible on any page
 */
import { useBackgroundScan } from "@/context/BackgroundScanContext";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useNavigate } from "react-router-dom";
import { Activity, CheckCircle, XCircle } from "lucide-react";

export const BackgroundScanIndicator = () => {
  const { activeScan } = useBackgroundScan();
  const navigate = useNavigate();

  if (!activeScan || activeScan.status === "completed") return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-50 bg-card border border-primary/30 rounded-lg shadow-lg p-3 cursor-pointer hover:border-primary/60 transition-all min-w-[280px]"
      onClick={() => navigate("/unified-vapt")}
    >
      <div className="flex items-center gap-2 mb-2">
        {activeScan.status === "running" ? (
          <Activity className="h-4 w-4 text-primary animate-pulse" />
        ) : (
          <XCircle className="h-4 w-4 text-destructive" />
        )}
        <span className="text-xs font-medium">VAPT Scan Active</span>
        <Badge variant="outline" className="text-[10px] ml-auto font-mono">
          {activeScan.target?.replace(/^https?:\/\//, "").slice(0, 25)}
        </Badge>
      </div>
      <Progress value={activeScan.progress} className="h-1.5 mb-1" />
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span>{activeScan.progress}% — {activeScan.phase}</span>
        <span>{activeScan.findings} findings</span>
      </div>
    </div>
  );
};
