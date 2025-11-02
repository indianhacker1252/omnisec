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
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    setNetworks([
      {
        ssid: "HomeNetwork_5G",
        bssid: "A4:CF:12:34:56:78",
        channel: 149,
        security: "WPA2-PSK",
        signal: -45,
        encryption: "CCMP",
        vulnerabilities: ["WPS Enabled", "Weak Password"],
        clients: 12,
      },
      {
        ssid: "OfficeWiFi",
        bssid: "B8:27:EB:A1:B2:C3",
        channel: 6,
        security: "WPA3",
        signal: -62,
        encryption: "CCMP",
        vulnerabilities: [],
        clients: 7,
      },
      {
        ssid: "GuestNetwork",
        bssid: "DC:9F:DB:12:34:56",
        channel: 11,
        security: "Open",
        signal: -78,
        encryption: "None",
        vulnerabilities: ["No Encryption", "Open Network"],
        clients: 3,
      },
      {
        ssid: "Corp_WiFi",
        bssid: "E2:3A:FF:12:88:99",
        channel: 36,
        security: "WPA-PSK",
        signal: -55,
        encryption: "TKIP",
        vulnerabilities: ["WPA1 Deprecated", "TKIP Vulnerable", "Possible KRACK"],
        clients: 23,
      },
    ]);
    setScanning(false);
    toast({ title: "Scan Complete", description: `Found ${4} wireless networks` });
  };

  const startBleScan = async () => {
    setScanning(true);
    toast({ title: "BLE Scan", description: "Scanning for Bluetooth devices..." });
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    setBleDevices([
      {
        name: "Samsung Galaxy S21",
        address: "AA:BB:CC:DD:EE:01",
        rssi: -67,
        services: ["Heart Rate", "Battery Service"],
        vulnerabilities: ["BlueBorne", "Unencrypted Pairing"],
      },
      {
        name: "Apple AirPods Pro",
        address: "AA:BB:CC:DD:EE:02",
        rssi: -45,
        services: ["Audio Sink", "AVRCP"],
        vulnerabilities: [],
      },
      {
        name: "Fitness Tracker",
        address: "AA:BB:CC:DD:EE:03",
        rssi: -82,
        services: ["Device Information", "Heart Rate"],
        vulnerabilities: ["Open Pairing", "No Authentication"],
      },
    ]);
    setScanning(false);
    toast({ title: "BLE Scan Complete", description: `Found ${3} Bluetooth devices` });
  };

  const startNfcScan = async () => {
    setScanning(true);
    toast({ title: "NFC Scan", description: "Scanning for NFC tags..." });
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    setNfcTags([
      {
        type: "MIFARE Classic 1K",
        uid: "04:A1:B2:C3:D4:E5:F6",
        size: "1KB",
        writable: true,
        vulnerabilities: ["Crypto1 Weakness", "Default Keys"],
      },
      {
        type: "NTAG213",
        uid: "04:B2:C3:D4:E5:F6:A1",
        size: "180 bytes",
        writable: false,
        vulnerabilities: [],
      },
    ]);
    setScanning(false);
    toast({ title: "NFC Scan Complete", description: `Found ${2} NFC tags` });
  };

  const startRfScan = async () => {
    setScanning(true);
    toast({ title: "RF Scan", description: "Analyzing radio frequency spectrum..." });
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    setRfSignals([
      {
        frequency: "433.92 MHz",
        modulation: "ASK/OOK",
        strength: -54,
        type: "Remote Control",
        description: "Garage door opener signal",
        vulnerable: true,
      },
      {
        frequency: "868.35 MHz",
        modulation: "FSK",
        strength: -62,
        type: "IoT Sensor",
        description: "Temperature sensor transmission",
        vulnerable: false,
      },
      {
        frequency: "315.00 MHz",
        modulation: "AM",
        strength: -48,
        type: "Key Fob",
        description: "Car remote keyless entry",
        vulnerable: true,
      },
    ]);
    setScanning(false);
    toast({ title: "RF Scan Complete", description: `Detected ${3} RF signals` });
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
