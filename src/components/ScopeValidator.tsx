/**
 * OmniSec™ Scope Validator & Engagement Configuration
 * Enterprise-grade authorization and scope management for VAPT engagements
 */

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileText,
  Plus,
  Trash2,
  Clock,
  Lock,
  Unlock,
  Globe,
  Server,
  Cloud,
  Smartphone,
  Wifi,
  Database,
  Key,
  Target,
  AlertCircle,
  Calendar,
  User,
  Building,
  FileCheck
} from "lucide-react";

interface ScopeEntry {
  id: string;
  type: 'domain' | 'ip' | 'cidr' | 'url' | 'cloud_account' | 'container' | 'wireless';
  value: string;
  status: 'approved' | 'pending' | 'excluded';
  notes?: string;
}

interface Engagement {
  id: string;
  name: string;
  client: string;
  startDate: string;
  endDate: string;
  status: 'draft' | 'active' | 'completed' | 'expired';
  scope: ScopeEntry[];
  rules: {
    allowDestructive: boolean;
    allowDenialOfService: boolean;
    allowSocialEngineering: boolean;
    allowPhysicalAccess: boolean;
    testingHours: { start: string; end: string };
    excludedPaths: string[];
    rateLimit: number;
    notifyOnCritical: boolean;
  };
  contacts: {
    primary: string;
    secondary: string;
    escalation: string;
  };
  authorization: {
    documentId?: string;
    signedBy?: string;
    signedDate?: string;
    verified: boolean;
  };
}

interface ScopeValidatorProps {
  onScopeValidated?: (engagement: Engagement) => void;
  onValidationChange?: (isValid: boolean) => void;
}

export const ScopeValidator = ({ onScopeValidated, onValidationChange }: ScopeValidatorProps) => {
  const { toast } = useToast();
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [activeEngagement, setActiveEngagement] = useState<Engagement | null>(null);
  const [newScopeEntry, setNewScopeEntry] = useState({ type: 'domain' as ScopeEntry['type'], value: '', notes: '' });
  const [isCreatingEngagement, setIsCreatingEngagement] = useState(false);
  const [validationResult, setValidationResult] = useState<{ valid: boolean; messages: string[] } | null>(null);

  // New engagement form
  const [newEngagement, setNewEngagement] = useState({
    name: '',
    client: '',
    startDate: new Date().toISOString().split('T')[0],
    endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    primaryContact: '',
    secondaryContact: '',
    escalationContact: '',
  });

  useEffect(() => {
    loadEngagements();
  }, []);

  const loadEngagements = async () => {
    try {
      const { data } = await supabase
        .from('vapt_config')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (data && data.length > 0) {
        const mappedEngagements: Engagement[] = data.map(item => ({
          id: item.id,
          name: `Engagement ${item.id.slice(0, 8)}`,
          client: 'Default Client',
          startDate: item.created_at,
          endDate: item.updated_at,
          status: item.mode === 'active' ? 'active' : 'draft',
          scope: (item.allowed_targets || []).map((t: string, i: number) => ({
            id: String(i),
            type: 'domain' as const,
            value: t,
            status: 'approved' as const
          })),
          rules: {
            allowDestructive: false,
            allowDenialOfService: false,
            allowSocialEngineering: false,
            allowPhysicalAccess: false,
            testingHours: { start: '09:00', end: '18:00' },
            excludedPaths: [],
            rateLimit: 100,
            notifyOnCritical: true
          },
          contacts: { primary: '', secondary: '', escalation: '' },
          authorization: { verified: false }
        }));
        setEngagements(mappedEngagements);
        if (mappedEngagements.find(e => e.status === 'active')) {
          setActiveEngagement(mappedEngagements.find(e => e.status === 'active') || null);
        }
      }
    } catch (e) {
      console.error('Failed to load engagements:', e);
    }
  };

  const createEngagement = async () => {
    const engagement: Engagement = {
      id: crypto.randomUUID(),
      name: newEngagement.name,
      client: newEngagement.client,
      startDate: newEngagement.startDate,
      endDate: newEngagement.endDate,
      status: 'draft',
      scope: [],
      rules: {
        allowDestructive: false,
        allowDenialOfService: false,
        allowSocialEngineering: false,
        allowPhysicalAccess: false,
        testingHours: { start: '09:00', end: '18:00' },
        excludedPaths: [],
        rateLimit: 100,
        notifyOnCritical: true
      },
      contacts: {
        primary: newEngagement.primaryContact,
        secondary: newEngagement.secondaryContact,
        escalation: newEngagement.escalationContact
      },
      authorization: { verified: false }
    };

    setEngagements(prev => [engagement, ...prev]);
    setActiveEngagement(engagement);
    setIsCreatingEngagement(false);
    
    // Save to database
    await supabase.from('vapt_config').insert({
      id: engagement.id,
      mode: 'draft',
      allowed_targets: [],
      log_level: 'info'
    });

    toast({ title: "Engagement Created", description: `${engagement.name} is ready for scope configuration` });
  };

  const addScopeEntry = () => {
    if (!activeEngagement || !newScopeEntry.value.trim()) return;

    const entry: ScopeEntry = {
      id: crypto.randomUUID(),
      type: newScopeEntry.type,
      value: newScopeEntry.value.trim(),
      status: 'pending',
      notes: newScopeEntry.notes
    };

    setActiveEngagement(prev => prev ? {
      ...prev,
      scope: [...prev.scope, entry]
    } : null);

    setNewScopeEntry({ type: 'domain', value: '', notes: '' });
    toast({ title: "Scope Entry Added", description: `${entry.value} added as ${entry.type}` });
  };

  const removeScopeEntry = (id: string) => {
    setActiveEngagement(prev => prev ? {
      ...prev,
      scope: prev.scope.filter(s => s.id !== id)
    } : null);
  };

  const updateScopeStatus = (id: string, status: ScopeEntry['status']) => {
    setActiveEngagement(prev => prev ? {
      ...prev,
      scope: prev.scope.map(s => s.id === id ? { ...s, status } : s)
    } : null);
  };

  const validateTarget = async (target: string): Promise<{ valid: boolean; reason: string }> => {
    if (!activeEngagement) {
      return { valid: false, reason: 'No active engagement configured' };
    }

    const now = new Date();
    const startDate = new Date(activeEngagement.startDate);
    const endDate = new Date(activeEngagement.endDate);

    // Check engagement dates
    if (now < startDate) {
      return { valid: false, reason: 'Engagement has not started yet' };
    }
    if (now > endDate) {
      return { valid: false, reason: 'Engagement has expired' };
    }

    // Check authorization
    if (!activeEngagement.authorization.verified) {
      return { valid: false, reason: 'Authorization document not verified' };
    }

    // Check if target is in scope
    const normalizedTarget = target.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    const inScope = activeEngagement.scope.some(s => {
      if (s.status !== 'approved') return false;
      const scopeValue = s.value.toLowerCase();
      switch (s.type) {
        case 'domain':
          return normalizedTarget === scopeValue || normalizedTarget.endsWith('.' + scopeValue);
        case 'ip':
        case 'url':
          return normalizedTarget === scopeValue || target.includes(scopeValue);
        case 'cidr':
          // Simplified CIDR check - in production would use proper IP parsing
          return normalizedTarget.startsWith(scopeValue.split('/')[0].replace(/\.\d+$/, ''));
        default:
          return normalizedTarget.includes(scopeValue);
      }
    });

    if (!inScope) {
      return { valid: false, reason: `Target "${target}" is not in approved scope` };
    }

    // Check excluded paths
    const isExcluded = activeEngagement.rules.excludedPaths.some(path => 
      target.toLowerCase().includes(path.toLowerCase())
    );
    if (isExcluded) {
      return { valid: false, reason: 'Target path is explicitly excluded from scope' };
    }

    // Check testing hours
    const currentHour = now.getHours();
    const startHour = parseInt(activeEngagement.rules.testingHours.start.split(':')[0]);
    const endHour = parseInt(activeEngagement.rules.testingHours.end.split(':')[0]);
    if (currentHour < startHour || currentHour >= endHour) {
      return { valid: false, reason: `Testing only allowed between ${activeEngagement.rules.testingHours.start} and ${activeEngagement.rules.testingHours.end}` };
    }

    return { valid: true, reason: 'Target is within authorized scope' };
  };

  const validateEngagement = async () => {
    if (!activeEngagement) return;

    const messages: string[] = [];
    let valid = true;

    // Check required fields
    if (!activeEngagement.name) {
      messages.push('❌ Engagement name is required');
      valid = false;
    }
    if (!activeEngagement.client) {
      messages.push('❌ Client name is required');
      valid = false;
    }
    if (activeEngagement.scope.length === 0) {
      messages.push('❌ At least one scope entry is required');
      valid = false;
    }
    if (activeEngagement.scope.filter(s => s.status === 'approved').length === 0) {
      messages.push('❌ At least one approved scope entry is required');
      valid = false;
    }
    if (!activeEngagement.authorization.verified) {
      messages.push('⚠️ Authorization document not verified');
      valid = false;
    }
    if (!activeEngagement.contacts.primary) {
      messages.push('⚠️ Primary contact not configured');
    }
    if (!activeEngagement.contacts.escalation) {
      messages.push('⚠️ Escalation contact not configured');
    }

    // Check dates
    const now = new Date();
    const endDate = new Date(activeEngagement.endDate);
    if (endDate < now) {
      messages.push('❌ Engagement end date is in the past');
      valid = false;
    }

    if (valid) {
      messages.unshift('✅ Engagement is properly configured and ready for testing');
    }

    setValidationResult({ valid, messages });
    onValidationChange?.(valid);

    if (valid) {
      onScopeValidated?.(activeEngagement);
      toast({ title: "Scope Validated", description: "Engagement is ready for authorized testing" });
    }

    return valid;
  };

  const activateEngagement = async () => {
    if (!activeEngagement) return;
    
    const isValid = await validateEngagement();
    if (!isValid) {
      toast({ title: "Validation Failed", description: "Please fix issues before activating", variant: "destructive" });
      return;
    }

    setActiveEngagement(prev => prev ? { ...prev, status: 'active' } : null);
    setEngagements(prev => prev.map(e => e.id === activeEngagement.id ? { ...e, status: 'active' } : e));

    // Update database
    await supabase.from('vapt_config').update({
      mode: 'active',
      allowed_targets: activeEngagement.scope.filter(s => s.status === 'approved').map(s => s.value),
      updated_at: new Date().toISOString()
    }).eq('id', activeEngagement.id);

    toast({ title: "Engagement Activated", description: "Testing can now begin within approved scope" });
  };

  const getTypeIcon = (type: ScopeEntry['type']) => {
    switch (type) {
      case 'domain': return <Globe className="h-4 w-4" />;
      case 'ip': return <Server className="h-4 w-4" />;
      case 'cidr': return <Database className="h-4 w-4" />;
      case 'url': return <Target className="h-4 w-4" />;
      case 'cloud_account': return <Cloud className="h-4 w-4" />;
      case 'container': return <Server className="h-4 w-4" />;
      case 'wireless': return <Wifi className="h-4 w-4" />;
      default: return <Globe className="h-4 w-4" />;
    }
  };

  const getStatusBadge = (status: ScopeEntry['status']) => {
    switch (status) {
      case 'approved': return <Badge className="bg-green-500/20 text-green-400">Approved</Badge>;
      case 'pending': return <Badge className="bg-yellow-500/20 text-yellow-400">Pending</Badge>;
      case 'excluded': return <Badge className="bg-red-500/20 text-red-400">Excluded</Badge>;
    }
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-primary/20">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold">Scope Validator & Engagement Manager</h2>
            <p className="text-sm text-muted-foreground">Enterprise authorization and scope configuration</p>
          </div>
        </div>
        <Dialog open={isCreatingEngagement} onOpenChange={setIsCreatingEngagement}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              New Engagement
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create New Engagement</DialogTitle>
            </DialogHeader>
            <div className="grid grid-cols-2 gap-4 py-4">
              <div>
                <label className="text-sm font-medium">Engagement Name</label>
                <Input
                  value={newEngagement.name}
                  onChange={(e) => setNewEngagement(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Q1 2026 Security Assessment"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Client Name</label>
                <Input
                  value={newEngagement.client}
                  onChange={(e) => setNewEngagement(prev => ({ ...prev, client: e.target.value }))}
                  placeholder="Acme Corporation"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Start Date</label>
                <Input
                  type="date"
                  value={newEngagement.startDate}
                  onChange={(e) => setNewEngagement(prev => ({ ...prev, startDate: e.target.value }))}
                />
              </div>
              <div>
                <label className="text-sm font-medium">End Date</label>
                <Input
                  type="date"
                  value={newEngagement.endDate}
                  onChange={(e) => setNewEngagement(prev => ({ ...prev, endDate: e.target.value }))}
                />
              </div>
              <div className="col-span-2">
                <label className="text-sm font-medium">Primary Contact</label>
                <Input
                  value={newEngagement.primaryContact}
                  onChange={(e) => setNewEngagement(prev => ({ ...prev, primaryContact: e.target.value }))}
                  placeholder="security@acme.com"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreatingEngagement(false)}>Cancel</Button>
              <Button onClick={createEngagement}>Create Engagement</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Active Engagement Status */}
      {activeEngagement && (
        <div className={`p-4 rounded-lg mb-6 ${activeEngagement.status === 'active' ? 'bg-green-500/10 border border-green-500/30' : 'bg-yellow-500/10 border border-yellow-500/30'}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {activeEngagement.status === 'active' ? (
                <Unlock className="h-5 w-5 text-green-500" />
              ) : (
                <Lock className="h-5 w-5 text-yellow-500" />
              )}
              <div>
                <h3 className="font-semibold">{activeEngagement.name}</h3>
                <p className="text-sm text-muted-foreground">
                  {activeEngagement.client} | {new Date(activeEngagement.startDate).toLocaleDateString()} - {new Date(activeEngagement.endDate).toLocaleDateString()}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={activeEngagement.status === 'active' ? 'default' : 'outline'}>
                {activeEngagement.status.toUpperCase()}
              </Badge>
              <Badge variant="outline">
                {activeEngagement.scope.filter(s => s.status === 'approved').length} targets
              </Badge>
            </div>
          </div>
        </div>
      )}

      <Tabs defaultValue="scope" className="w-full">
        <TabsList className="grid w-full grid-cols-4 mb-4">
          <TabsTrigger value="scope" className="gap-2">
            <Target className="h-4 w-4" />
            Scope
          </TabsTrigger>
          <TabsTrigger value="rules" className="gap-2">
            <Shield className="h-4 w-4" />
            Rules
          </TabsTrigger>
          <TabsTrigger value="authorization" className="gap-2">
            <FileCheck className="h-4 w-4" />
            Authorization
          </TabsTrigger>
          <TabsTrigger value="validation" className="gap-2">
            <CheckCircle className="h-4 w-4" />
            Validate
          </TabsTrigger>
        </TabsList>

        <TabsContent value="scope">
          <div className="space-y-4">
            {/* Add Scope Entry */}
            <div className="flex gap-2">
              <Select
                value={newScopeEntry.type}
                onValueChange={(v: ScopeEntry['type']) => setNewScopeEntry(prev => ({ ...prev, type: v }))}
              >
                <SelectTrigger className="w-[140px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="cidr">CIDR Range</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="cloud_account">Cloud Account</SelectItem>
                  <SelectItem value="container">Container/K8s</SelectItem>
                  <SelectItem value="wireless">Wireless</SelectItem>
                </SelectContent>
              </Select>
              <Input
                className="flex-1"
                value={newScopeEntry.value}
                onChange={(e) => setNewScopeEntry(prev => ({ ...prev, value: e.target.value }))}
                placeholder="Enter target (e.g., example.com, 192.168.1.0/24)"
              />
              <Button onClick={addScopeEntry} disabled={!activeEngagement}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {/* Scope Entries */}
            <ScrollArea className="h-[300px]">
              <div className="space-y-2">
                {activeEngagement?.scope.map(entry => (
                  <Card key={entry.id} className="p-3 bg-background/50">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getTypeIcon(entry.type)}
                        <div>
                          <code className="text-sm font-mono">{entry.value}</code>
                          <p className="text-xs text-muted-foreground">{entry.type}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusBadge(entry.status)}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => updateScopeStatus(entry.id, entry.status === 'approved' ? 'pending' : 'approved')}
                        >
                          {entry.status === 'approved' ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => removeScopeEntry(entry.id)}>
                          <Trash2 className="h-3 w-3 text-red-400" />
                        </Button>
                      </div>
                    </div>
                  </Card>
                ))}
                {(!activeEngagement || activeEngagement.scope.length === 0) && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No scope entries defined</p>
                    <p className="text-sm">Add domains, IPs, or other targets above</p>
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
        </TabsContent>

        <TabsContent value="rules">
          {activeEngagement ? (
            <div className="space-y-4">
              <Card className="p-4 bg-background/50">
                <h4 className="font-medium mb-4">Testing Restrictions</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Allow Destructive Tests</span>
                    <Switch
                      checked={activeEngagement.rules.allowDestructive}
                      onCheckedChange={(v) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, allowDestructive: v } } : null)}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Allow DoS Testing</span>
                    <Switch
                      checked={activeEngagement.rules.allowDenialOfService}
                      onCheckedChange={(v) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, allowDenialOfService: v } } : null)}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Allow Social Engineering</span>
                    <Switch
                      checked={activeEngagement.rules.allowSocialEngineering}
                      onCheckedChange={(v) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, allowSocialEngineering: v } } : null)}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Notify on Critical Findings</span>
                    <Switch
                      checked={activeEngagement.rules.notifyOnCritical}
                      onCheckedChange={(v) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, notifyOnCritical: v } } : null)}
                    />
                  </div>
                </div>
              </Card>

              <Card className="p-4 bg-background/50">
                <h4 className="font-medium mb-4">Testing Schedule</h4>
                <div className="flex items-center gap-4">
                  <div>
                    <label className="text-sm text-muted-foreground">Start Time</label>
                    <Input
                      type="time"
                      value={activeEngagement.rules.testingHours.start}
                      onChange={(e) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, testingHours: { ...prev.rules.testingHours, start: e.target.value } } } : null)}
                    />
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">End Time</label>
                    <Input
                      type="time"
                      value={activeEngagement.rules.testingHours.end}
                      onChange={(e) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, testingHours: { ...prev.rules.testingHours, end: e.target.value } } } : null)}
                    />
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Rate Limit (req/min)</label>
                    <Input
                      type="number"
                      value={activeEngagement.rules.rateLimit}
                      onChange={(e) => setActiveEngagement(prev => prev ? { ...prev, rules: { ...prev.rules, rateLimit: parseInt(e.target.value) || 100 } } : null)}
                    />
                  </div>
                </div>
              </Card>

              <Card className="p-4 bg-background/50">
                <h4 className="font-medium mb-4">Excluded Paths</h4>
                <Textarea
                  placeholder="/admin, /backup, /internal (one per line or comma-separated)"
                  value={activeEngagement.rules.excludedPaths.join(', ')}
                  onChange={(e) => setActiveEngagement(prev => prev ? { 
                    ...prev, 
                    rules: { 
                      ...prev.rules, 
                      excludedPaths: e.target.value.split(/[,\n]/).map(p => p.trim()).filter(Boolean) 
                    } 
                  } : null)}
                />
              </Card>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>Select or create an engagement to configure rules</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="authorization">
          {activeEngagement ? (
            <div className="space-y-4">
              <Card className={`p-4 ${activeEngagement.authorization.verified ? 'bg-green-500/10 border-green-500/30' : 'bg-yellow-500/10 border-yellow-500/30'}`}>
                <div className="flex items-center gap-3 mb-4">
                  {activeEngagement.authorization.verified ? (
                    <CheckCircle className="h-6 w-6 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-6 w-6 text-yellow-500" />
                  )}
                  <div>
                    <h4 className="font-medium">Authorization Status</h4>
                    <p className="text-sm text-muted-foreground">
                      {activeEngagement.authorization.verified 
                        ? 'Authorization verified and approved'
                        : 'Authorization pending verification'}
                    </p>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium">Signed By</label>
                    <Input
                      placeholder="John Smith, CISO"
                      value={activeEngagement.authorization.signedBy || ''}
                      onChange={(e) => setActiveEngagement(prev => prev ? { 
                        ...prev, 
                        authorization: { ...prev.authorization, signedBy: e.target.value } 
                      } : null)}
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Signed Date</label>
                    <Input
                      type="date"
                      value={activeEngagement.authorization.signedDate || ''}
                      onChange={(e) => setActiveEngagement(prev => prev ? { 
                        ...prev, 
                        authorization: { ...prev.authorization, signedDate: e.target.value } 
                      } : null)}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Verify Authorization</span>
                    <Switch
                      checked={activeEngagement.authorization.verified}
                      onCheckedChange={(v) => setActiveEngagement(prev => prev ? { 
                        ...prev, 
                        authorization: { ...prev.authorization, verified: v } 
                      } : null)}
                    />
                  </div>
                </div>
              </Card>

              <Card className="p-4 bg-background/50">
                <h4 className="font-medium mb-2">⚠️ Legal Notice</h4>
                <p className="text-sm text-muted-foreground">
                  By activating this engagement, you confirm that you have written authorization to perform 
                  security testing on all targets in scope. Unauthorized access to computer systems is illegal 
                  and may violate laws including the Computer Fraud and Abuse Act (CFAA), GDPR, and other 
                  applicable regulations.
                </p>
              </Card>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <FileCheck className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>Select or create an engagement to manage authorization</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="validation">
          <div className="space-y-4">
            <Button onClick={validateEngagement} className="w-full gap-2">
              <CheckCircle className="h-4 w-4" />
              Validate Engagement
            </Button>

            {validationResult && (
              <Card className={`p-4 ${validationResult.valid ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                <div className="space-y-2">
                  {validationResult.messages.map((msg, i) => (
                    <p key={i} className="text-sm">{msg}</p>
                  ))}
                </div>
              </Card>
            )}

            {activeEngagement && validationResult?.valid && activeEngagement.status !== 'active' && (
              <Button onClick={activateEngagement} className="w-full gap-2" variant="default">
                <Unlock className="h-4 w-4" />
                Activate Engagement
              </Button>
            )}

            {activeEngagement?.status === 'active' && (
              <Card className="p-4 bg-green-500/10 border-green-500/30">
                <div className="flex items-center gap-2 text-green-400">
                  <CheckCircle className="h-5 w-5" />
                  <span className="font-medium">Engagement is ACTIVE - Testing authorized</span>
                </div>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </Card>
  );
};

export default ScopeValidator;
