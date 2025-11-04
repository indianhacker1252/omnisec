/**
 * OmniSec™ Wireless Security Module
 * © 2024 HARSH MALIK. All Rights Reserved.
 * Patent Pending - Unified VAPT Platform
 */

import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState } from "react";
import { Wifi, Bluetooth, Radio, Loader2, Signal, ArrowLeft, Shield, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

const WirelessModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [scanning, setScanning] = useState(false);
  const [networks, setNetworks] = useState<any[]>([]);
  const [bleDevices, setBleDevices] = useState<any[]>([]);
  const [nfcTags, setNfcTags] = useState<any[]>([]);
  const [rfSignals, setRfSignals] = useState<any[]>([]);

  const startScan = async () => {
    setScanning(true);
    toast({ title: "WiFi Scan", description: "Scanning for wireless networks..." });
    
    try {
      const { data, error } = await supabase.functions.invoke('wireless-scan', {
        body: { scanType: 'wifi' }
      });

      if (error) throw error;
      
      setNetworks(data.results || []);
      setScanning(false);
      toast({ 
        title: "Scan Complete", 
        description: `Found ${data.results?.length || 0} wireless networks` 
      });
    } catch (error: any) {
      console.error('WiFi scan error:', error);
      setScanning(false);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to scan wireless networks",
        variant: "destructive"
      });
    }
  };

  const startBleScan = async () => {
    setScanning(true);
    toast({ title: "BLE Scan", description: "Scanning for Bluetooth devices..." });
    
    try {
      const { data, error } = await supabase.functions.invoke('wireless-scan', {
        body: { scanType: 'bluetooth' }
      });

      if (error) throw error;
      
      setBleDevices(data.results || []);
      setScanning(false);
      toast({ 
        title: "BLE Scan Complete", 
        description: `Found ${data.results?.length || 0} Bluetooth devices` 
      });
    } catch (error: any) {
      console.error('BLE scan error:', error);
      setScanning(false);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to scan Bluetooth devices",
        variant: "destructive"
      });
    }
  };

  const startNfcScan = async () => {
    setScanning(true);
    toast({ title: "NFC Scan", description: "Scanning for NFC tags..." });
    
    try {
      const { data, error } = await supabase.functions.invoke('wireless-scan', {
        body: { scanType: 'nfc' }
      });

      if (error) throw error;
      
      setNfcTags(data.results || []);
      setScanning(false);
      toast({ 
        title: "NFC Scan Complete", 
        description: `Found ${data.results?.length || 0} NFC tags` 
      });
    } catch (error: any) {
      console.error('NFC scan error:', error);
      setScanning(false);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to scan NFC tags",
        variant: "destructive"
      });
    }
  };

  const startRfScan = async () => {
    setScanning(true);
    toast({ title: "RF Scan", description: "Analyzing radio frequency spectrum..." });
    
    try {
      const { data, error } = await supabase.functions.invoke('wireless-scan', {
        body: { scanType: 'rf' }
      });

      if (error) throw error;
      
      setRfSignals(data.results || []);
      setScanning(false);
      toast({ 
        title: "RF Scan Complete", 
        description: `Detected ${data.results?.length || 0} RF signals` 
      });
    } catch (error: any) {
      console.error('RF scan error:', error);
      setScanning(false);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to scan RF spectrum",
        variant: "destructive"
      });
    }
  };

  const getSignalStrength = (signal: number) => {
    if (signal > -50) return { label: "Excellent", color: "text-green-500" };
    if (signal > -60) return { label: "Good", color: "text-cyan-500" };
    if (signal > -70) return { label: "Fair", color: "text-yellow-500" };
    return { label: "Weak", color: "text-red-500" };
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Wifi className="h-8 w-8 text-cyber-cyan" />
            <h1 className="text-3xl font-bold font-mono">Wireless Security</h1>
          </div>
          <p className="text-muted-foreground">
            WiFi, Bluetooth, NFC, and RF analysis toolkit
          </p>
        </div>

        <Tabs defaultValue="wifi" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="wifi">
              <Wifi className="h-4 w-4 mr-2" />
              WiFi
            </TabsTrigger>
            <TabsTrigger value="bluetooth">
              <Bluetooth className="h-4 w-4 mr-2" />
              Bluetooth
            </TabsTrigger>
            <TabsTrigger value="nfc">
              <Radio className="h-4 w-4 mr-2" />
              NFC
            </TabsTrigger>
            <TabsTrigger value="rf">
              <Signal className="h-4 w-4 mr-2" />
              RF Analysis
            </TabsTrigger>
          </TabsList>

          <TabsContent value="wifi" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">WiFi Scanner</h3>
                <Button onClick={startScan} disabled={scanning}>
                  {scanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Wifi className="mr-2 h-4 w-4" />
                      Start Scan
                    </>
                  )}
                </Button>
              </div>

              {networks.length > 0 && (
                <div className="space-y-3">
                  {networks.map((network, idx) => {
                    const signal = getSignalStrength(network.signal);
                    const hasVulns = network.vulnerabilities.length > 0;
                    return (
                      <Card key={idx} className={`p-4 ${hasVulns ? 'border-red-500/50' : 'border-cyber-cyan/30'}`}>
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h4 className="font-semibold font-mono">{network.ssid}</h4>
                            <p className="text-xs text-muted-foreground font-mono">
                              {network.bssid}
                            </p>
                          </div>
                          <div className="flex gap-2">
                            <Badge
                              variant={
                                network.security === "Open" ? "destructive" : "default"
                              }
                            >
                              {network.security}
                            </Badge>
                            {hasVulns && (
                              <Badge variant="destructive">
                                <AlertTriangle className="h-3 w-3 mr-1" />
                                {network.vulnerabilities.length}
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs mb-2">
                          <div>
                            <span className="text-muted-foreground">Channel:</span>
                            <span className="ml-1 font-mono">{network.channel}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Signal:</span>
                            <span className={`ml-1 font-mono ${signal.color}`}>
                              {network.signal} dBm ({signal.label})
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Encryption:</span>
                            <span className="ml-1 font-mono">{network.encryption}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Clients:</span>
                            <span className="ml-1 font-mono">{network.clients}</span>
                          </div>
                        </div>
                        {hasVulns && (
                          <div className="mt-2 p-2 bg-destructive/10 rounded">
                            <div className="text-xs font-semibold text-destructive mb-1">Vulnerabilities:</div>
                            <div className="flex flex-wrap gap-1">
                              {network.vulnerabilities.map((vuln: string, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs border-destructive text-destructive">
                                  {vuln}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </Card>
                    );
                  })}
                </div>
              )}

              {!scanning && networks.length === 0 && (
                <div className="text-center py-8">
                  <Wifi className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">
                    Click "Start Scan" to discover nearby wireless networks
                  </p>
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="bluetooth" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Bluetooth LE Scanner</h3>
                <Button onClick={startBleScan} disabled={scanning}>
                  {scanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Bluetooth className="mr-2 h-4 w-4" />
                      Start BLE Scan
                    </>
                  )}
                </Button>
              </div>

              {bleDevices.length > 0 && (
                <div className="space-y-3">
                  {bleDevices.map((device, idx) => (
                    <Card key={idx} className={`p-4 ${device.vulnerabilities.length > 0 ? 'border-red-500/50' : 'border-cyber-cyan/30'}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-semibold font-mono">{device.name}</h4>
                          <p className="text-xs text-muted-foreground font-mono">{device.address}</p>
                        </div>
                        <Badge>{device.rssi} dBm</Badge>
                      </div>
                      <div className="text-xs mb-2">
                        <span className="text-muted-foreground">Services: </span>
                        <span>{device.services.join(", ")}</span>
                      </div>
                      {device.vulnerabilities.length > 0 && (
                        <div className="mt-2 p-2 bg-destructive/10 rounded">
                          <div className="flex flex-wrap gap-1">
                            {device.vulnerabilities.map((vuln: string, i: number) => (
                              <Badge key={i} variant="outline" className="text-xs border-destructive text-destructive">
                                {vuln}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </Card>
                  ))}
                </div>
              )}

              {!scanning && bleDevices.length === 0 && (
                <div className="text-center py-8">
                  <Bluetooth className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">Click "Start BLE Scan" to discover Bluetooth devices</p>
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="nfc" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">NFC Tag Scanner</h3>
                <Button onClick={startNfcScan} disabled={scanning}>
                  {scanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Radio className="mr-2 h-4 w-4" />
                      Start NFC Scan
                    </>
                  )}
                </Button>
              </div>

              {nfcTags.length > 0 && (
                <div className="space-y-3">
                  {nfcTags.map((tag, idx) => (
                    <Card key={idx} className={`p-4 ${tag.vulnerabilities.length > 0 ? 'border-red-500/50' : 'border-cyber-cyan/30'}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-semibold font-mono">{tag.type}</h4>
                          <p className="text-xs text-muted-foreground font-mono">UID: {tag.uid}</p>
                        </div>
                        <div className="flex gap-2">
                          <Badge>{tag.size}</Badge>
                          {tag.writable && <Badge variant="outline">Writable</Badge>}
                        </div>
                      </div>
                      {tag.vulnerabilities.length > 0 && (
                        <div className="mt-2 p-2 bg-destructive/10 rounded">
                          <div className="flex flex-wrap gap-1">
                            {tag.vulnerabilities.map((vuln: string, i: number) => (
                              <Badge key={i} variant="outline" className="text-xs border-destructive text-destructive">
                                {vuln}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </Card>
                  ))}
                </div>
              )}

              {!scanning && nfcTags.length === 0 && (
                <div className="text-center py-8">
                  <Radio className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">Click "Start NFC Scan" to detect nearby NFC tags</p>
                </div>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="rf" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">RF Spectrum Analyzer</h3>
                <Button onClick={startRfScan} disabled={scanning}>
                  {scanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Signal className="mr-2 h-4 w-4" />
                      Start RF Scan
                    </>
                  )}
                </Button>
              </div>

              {rfSignals.length > 0 && (
                <div className="space-y-3">
                  {rfSignals.map((signal, idx) => (
                    <Card key={idx} className={`p-4 ${signal.vulnerable ? 'border-red-500/50' : 'border-cyber-cyan/30'}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-semibold font-mono">{signal.frequency}</h4>
                          <p className="text-xs text-muted-foreground">{signal.description}</p>
                        </div>
                        <div className="flex gap-2">
                          <Badge>{signal.strength} dBm</Badge>
                          {signal.vulnerable && (
                            <Badge variant="destructive">
                              <Shield className="h-3 w-3 mr-1" />
                              Vulnerable
                            </Badge>
                          )}
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>
                          <span className="text-muted-foreground">Type: </span>
                          <span className="font-mono">{signal.type}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Modulation: </span>
                          <span className="font-mono">{signal.modulation}</span>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              )}

              {!scanning && rfSignals.length === 0 && (
                <div className="text-center py-8">
                  <Signal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">Click "Start RF Scan" to analyze radio frequency spectrum</p>
                </div>
              )}
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default WirelessModule;
