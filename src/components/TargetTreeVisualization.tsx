/**
 * Target Tree Visualization Component
 * Visual tree graph: domain → subdomains → endpoints → tech → ports → vulns
 */
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Globe, Server, Network, Bug, Shield, ChevronDown, ChevronRight,
  Wifi, FolderOpen, Code, Lock, AlertTriangle
} from "lucide-react";

interface TreeNode {
  name: string;
  type: 'domain' | 'subdomain' | 'endpoint' | 'technology' | 'port' | 'vulnerability';
  status?: string;
  children: TreeNode[];
  meta?: Record<string, any>;
}

interface Props {
  tree: TreeNode;
}

const NODE_ICONS: Record<string, any> = {
  domain: Globe,
  subdomain: Network,
  endpoint: FolderOpen,
  technology: Code,
  port: Wifi,
  vulnerability: Bug,
};

const NODE_COLORS: Record<string, string> = {
  domain: "text-primary",
  subdomain: "text-blue-400",
  endpoint: "text-yellow-400",
  technology: "text-green-400",
  port: "text-orange-400",
  vulnerability: "text-destructive",
};

const TreeNodeRow = ({ node, depth = 0 }: { node: TreeNode; depth?: number }) => {
  const [expanded, setExpanded] = useState(depth < 2);
  const Icon = NODE_ICONS[node.type] || Globe;
  const color = NODE_COLORS[node.type] || "text-muted-foreground";
  const hasChildren = node.children?.length > 0;

  return (
    <div>
      <div
        className={`flex items-center gap-1.5 py-1 px-2 rounded hover:bg-primary/5 cursor-pointer transition-colors text-sm`}
        style={{ paddingLeft: `${depth * 20 + 8}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {hasChildren ? (
          expanded ? <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" /> : <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
        ) : (
          <span className="w-3 shrink-0" />
        )}
        <Icon className={`h-3.5 w-3.5 shrink-0 ${color}`} />
        <span className={`font-mono text-xs truncate ${color}`}>{node.name}</span>
        {node.type === 'vulnerability' && node.meta?.cwe && (
          <Badge variant="outline" className="text-[9px] ml-1 shrink-0">{node.meta.cwe}</Badge>
        )}
        {node.type === 'vulnerability' && node.meta?.confidence && (
          <Badge variant="outline" className="text-[9px] ml-1 shrink-0">{node.meta.confidence}%</Badge>
        )}
        {node.type === 'endpoint' && node.meta?.vulnCount > 0 && (
          <Badge className="text-[9px] ml-1 shrink-0 bg-destructive/20 text-destructive border-destructive/50">
            {node.meta.vulnCount} vulns
          </Badge>
        )}
        {node.type === 'port' && (
          <Badge variant="outline" className="text-[9px] ml-1 shrink-0">Port {node.meta?.port}</Badge>
        )}
        {hasChildren && (
          <span className="text-[10px] text-muted-foreground ml-auto shrink-0">({node.children.length})</span>
        )}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children.map((child, i) => (
            <TreeNodeRow key={`${child.name}-${i}`} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

export const TargetTreeVisualization = ({ tree }: Props) => {
  if (!tree || !tree.children?.length) return null;

  const totalVulns = countType(tree, 'vulnerability');
  const totalEndpoints = countType(tree, 'endpoint');
  const totalSubs = countType(tree, 'subdomain');

  return (
    <Card className="p-4 border-primary/20">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Network className="h-5 w-5 text-primary" />
          <h3 className="font-bold text-lg">Target Infrastructure Tree</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Badge variant="outline">{totalSubs} subdomains</Badge>
          <Badge variant="outline">{totalEndpoints} endpoints</Badge>
          <Badge variant="outline" className="border-destructive/50 text-destructive">{totalVulns} vulns</Badge>
        </div>
      </div>
      <ScrollArea className="h-72 bg-background/50 rounded border border-border/40 p-2">
        <TreeNodeRow node={tree} />
      </ScrollArea>
    </Card>
  );
};

function countType(node: TreeNode, type: string): number {
  let count = node.type === type ? 1 : 0;
  for (const child of (node.children || [])) {
    count += countType(child, type);
  }
  return count;
}
