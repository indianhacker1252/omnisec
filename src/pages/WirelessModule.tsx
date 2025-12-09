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
import { Wifi, Bluetooth, Radio, Signal, ArrowLeft, AlertTriangle, Terminal, ExternalLink } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface HardwareRequirement {
  title: string;
  steps: string[];
  tools: Record<string, string[]>;
  alternatives: string[];
}

const WirelessModule = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [requirements, setRequirements] = useState<HardwareRequirement | null>(null);
  const [activeTab, setActiveTab] = useState("wifi");

  const showRequirements = async (scanType: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('wireless-scan', {
        body: { scanType }
      });

      if (error || data?.error === "LOCAL_HARDWARE_REQUIRED") {
        setRequirements(data?.instructions || null);
        toast({
          title: "Local Hardware Required",
          description: "Wireless scanning requires physical hardware access",
          variant: "destructive"
        });
      }
    } catch (error: any) {
      console.error('Wireless scan error:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to check requirements",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <CommandHeader />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-6 flex items-center gap-4">
          <Button variant="outline" onClick={() => navigate('/')} className="gap-2 border-cyber-purple/30">
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

        {/* Hardware Requirement Notice */}
        <Card className="p-6 mb-6 bg-yellow-500/10 border-yellow-500/50">
          <div className="flex items-start gap-4">
            <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-1" />
            <div>
              <h3 className="font-semibold text-yellow-500 mb-2">Local Hardware Required</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Wireless scanning requires physical hardware access (WiFi adapter in monitor mode, Bluetooth adapter, NFC reader). 
                Cloud-based wireless scanning is not possible due to hardware requirements.
              </p>
              <div className="flex gap-3">
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => navigate('/kali-integration')}
                  className="gap-2 border-yellow-500/50 text-yellow-500 hover:bg-yellow-500/10"
                >
                  <Terminal className="h-4 w-4" />
                  Use Kali Integration
                </Button>
                <Button 
                  variant="ghost" 
                  size="sm"
                  onClick={() => showRequirements(activeTab)}
                  className="gap-2"
                >
                  <ExternalLink className="h-4 w-4" />
                  View Setup Guide
                </Button>
              </div>
            </div>
          </div>
        </Card>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
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
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">WiFi Security Testing</h3>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Required Hardware</h4>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-center gap-2">
                      <Badge variant="outline">Required</Badge>
                      Monitor mode capable WiFi adapter
                    </li>
                    <li className="flex items-center gap-2">
                      <Badge variant="secondary">Recommended</Badge>
                      Alfa AWUS036ACH, TP-Link TL-WN722N
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Recommended Tools</h4>
                  <div className="flex flex-wrap gap-2">
                    <Badge>aircrack-ng</Badge>
                    <Badge>kismet</Badge>
                    <Badge>wifite</Badge>
                    <Badge>bettercap</Badge>
                    <Badge>hashcat</Badge>
                  </div>
                </div>
              </div>
              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <h4 className="font-medium mb-2">Quick Start Commands</h4>
                <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Enable monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Capture handshake (authorized testing only)
sudo airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon`}
                </pre>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="bluetooth" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">Bluetooth Security Testing</h3>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Required Hardware</h4>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-center gap-2">
                      <Badge variant="outline">Required</Badge>
                      Bluetooth 4.0+ adapter with BLE support
                    </li>
                    <li className="flex items-center gap-2">
                      <Badge variant="secondary">Recommended</Badge>
                      Sena UD100, Ubertooth One (advanced)
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Recommended Tools</h4>
                  <div className="flex flex-wrap gap-2">
                    <Badge>hcitool</Badge>
                    <Badge>btscanner</Badge>
                    <Badge>bettercap</Badge>
                    <Badge>gatttool</Badge>
                    <Badge>bleah</Badge>
                  </div>
                </div>
              </div>
              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <h4 className="font-medium mb-2">Quick Start Commands</h4>
                <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Check Bluetooth adapter
hciconfig

# Enable adapter
sudo hciconfig hci0 up

# Scan for devices
sudo hcitool scan

# BLE scan
sudo hcitool lescan`}
                </pre>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="nfc" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">NFC Security Testing</h3>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Required Hardware</h4>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-center gap-2">
                      <Badge variant="outline">Required</Badge>
                      NFC reader (ACR122U, PN532)
                    </li>
                    <li className="flex items-center gap-2">
                      <Badge variant="secondary">Advanced</Badge>
                      Proxmark3, ChameleonMini
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Recommended Tools</h4>
                  <div className="flex flex-wrap gap-2">
                    <Badge>libnfc</Badge>
                    <Badge>mfoc</Badge>
                    <Badge>mfcuk</Badge>
                    <Badge>nfc-tools</Badge>
                  </div>
                </div>
              </div>
              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <h4 className="font-medium mb-2">Quick Start Commands</h4>
                <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# List NFC devices
nfc-list

# Read MIFARE Classic
mfoc -O output.dmp

# Scan NFC tag
nfc-poll`}
                </pre>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="rf" className="space-y-4">
            <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
              <h3 className="text-lg font-semibold mb-4">RF Spectrum Analysis</h3>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Required Hardware</h4>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-center gap-2">
                      <Badge variant="outline">Entry Level</Badge>
                      RTL-SDR dongle (~$25)
                    </li>
                    <li className="flex items-center gap-2">
                      <Badge variant="secondary">Advanced</Badge>
                      HackRF One, YARD Stick One
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Recommended Tools</h4>
                  <div className="flex flex-wrap gap-2">
                    <Badge>GNU Radio</Badge>
                    <Badge>GQRX</Badge>
                    <Badge>rtl_433</Badge>
                    <Badge>URH</Badge>
                  </div>
                </div>
              </div>
              <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                <h4 className="font-medium mb-2">Quick Start Commands</h4>
                <pre className="text-xs font-mono text-muted-foreground overflow-x-auto">
{`# Test RTL-SDR
rtl_test

# FM radio reception test
rtl_fm -f 100.1M -M wbfm | aplay -r 32000 -f S16_LE

# Decode wireless sensors
rtl_433 -f 433920000`}
                </pre>
              </div>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Setup Guide Modal Content */}
        {requirements && (
          <Card className="mt-6 p-6 border-cyber-cyan/50">
            <h3 className="text-lg font-semibold mb-4">Setup Guide</h3>
            <div className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Steps</h4>
                <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                  {requirements.steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
              {requirements.alternatives && (
                <div>
                  <h4 className="font-medium mb-2">Alternatives</h4>
                  <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                    {requirements.alternatives.map((alt, i) => (
                      <li key={i}>{alt}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </Card>
        )}
      </main>
    </div>
  );
};

export default WirelessModule;
