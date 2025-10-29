import { CommandHeader } from "@/components/CommandHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState } from "react";
import { Wifi, Bluetooth, Radio, Loader2, Signal } from "lucide-react";

const WirelessModule = () => {
  const [scanning, setScanning] = useState(false);
  const [networks, setNetworks] = useState<any[]>([]);

  const startScan = async () => {
    setScanning(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    setNetworks([
      {
        ssid: "HomeNetwork_5G",
        bssid: "A4:CF:12:34:56:78",
        channel: 149,
        security: "WPA2-PSK",
        signal: -45,
        encryption: "CCMP",
      },
      {
        ssid: "OfficeWiFi",
        bssid: "B8:27:EB:A1:B2:C3",
        channel: 6,
        security: "WPA3",
        signal: -62,
        encryption: "CCMP",
      },
      {
        ssid: "GuestNetwork",
        bssid: "DC:9F:DB:12:34:56",
        channel: 11,
        security: "Open",
        signal: -78,
        encryption: "None",
      },
    ]);
    setScanning(false);
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
                    return (
                      <Card key={idx} className="p-4 border-cyber-cyan/30">
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h4 className="font-semibold font-mono">{network.ssid}</h4>
                            <p className="text-xs text-muted-foreground font-mono">
                              {network.bssid}
                            </p>
                          </div>
                          <Badge
                            variant={
                              network.security === "Open" ? "destructive" : "default"
                            }
                          >
                            {network.security}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
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
                        </div>
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

          <TabsContent value="bluetooth">
            <Card className="p-6 text-center border-dashed">
              <Bluetooth className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                Bluetooth Low Energy (BLE) scanner and analyzer
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                Feature under development
              </p>
            </Card>
          </TabsContent>

          <TabsContent value="nfc">
            <Card className="p-6 text-center border-dashed">
              <Radio className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                Near Field Communication (NFC) reader and analyzer
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                Feature under development
              </p>
            </Card>
          </TabsContent>

          <TabsContent value="rf">
            <Card className="p-6 text-center border-dashed">
              <Signal className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                Radio Frequency spectrum analyzer and signal decoder
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                Feature under development
              </p>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default WirelessModule;
