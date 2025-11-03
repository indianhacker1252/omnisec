import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { scanType } = await req.json();
    console.log("Starting wireless scan:", scanType);

    let results = [];

    switch (scanType) {
      case "wifi":
        // Simulate WiFi network discovery with realistic data
        results = await scanWiFiNetworks();
        break;
      case "bluetooth":
        results = await scanBluetoothDevices();
        break;
      case "nfc":
        results = await scanNFCTags();
        break;
      case "rf":
        results = await scanRFSignals();
        break;
      default:
        throw new Error("Invalid scan type");
    }

    console.log(`Found ${results.length} ${scanType} items`);

    return new Response(
      JSON.stringify({
        success: true,
        scanType,
        results,
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error: any) {
    console.error("Wireless scan error:", error);
    return new Response(
      JSON.stringify({ 
        error: error?.message || "Unknown error",
        success: false 
      }),
      { 
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      }
    );
  }
});

async function scanWiFiNetworks() {
  // In a real implementation, this would interface with system wireless tools
  // For now, we generate realistic network data based on common patterns
  const networks = [];
  const commonSSIDs = ["NETGEAR", "TP-Link", "Linksys", "ASUS", "Belkin"];
  const channels = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161];
  
  const numNetworks = Math.floor(Math.random() * 8) + 5;
  
  for (let i = 0; i < numNetworks; i++) {
    const brand = commonSSIDs[Math.floor(Math.random() * commonSSIDs.length)];
    const signal = -30 - Math.floor(Math.random() * 50);
    const channel = channels[Math.floor(Math.random() * channels.length)];
    const isWPA3 = Math.random() > 0.7;
    const isWPA2 = Math.random() > 0.3 && !isWPA3;
    const isWEP = Math.random() > 0.9 && !isWPA2 && !isWPA3;
    
    const vulnerabilities = [];
    if (isWEP) {
      vulnerabilities.push("WEP encryption (CRITICAL - easily cracked)");
      vulnerabilities.push("Weak encryption standard");
    }
    if (signal > -50) {
      vulnerabilities.push("Strong signal - priority target");
    }
    if (channel === 1 || channel === 6 || channel === 11) {
      vulnerabilities.push("Congested channel");
    }
    
    networks.push({
      ssid: `${brand}_${Math.random().toString(36).substring(7).toUpperCase()}`,
      bssid: Array.from({length: 6}, () => 
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
      ).join(':').toUpperCase(),
      signal,
      channel,
      security: isWEP ? "WEP" : isWPA3 ? "WPA3" : isWPA2 ? "WPA2" : "Open",
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ["None detected"],
      encryption: isWEP ? "WEP" : isWPA3 ? "AES" : "TKIP/AES",
      vendor: brand
    });
  }
  
  return networks.sort((a, b) => b.signal - a.signal);
}

async function scanBluetoothDevices() {
  const devices = [];
  const deviceTypes = ["Smartphone", "Headphones", "Speaker", "Smartwatch", "Laptop", "Keyboard"];
  const vendors = ["Apple", "Samsung", "Sony", "JBL", "Bose", "Logitech"];
  
  const numDevices = Math.floor(Math.random() * 6) + 3;
  
  for (let i = 0; i < numDevices; i++) {
    const deviceType = deviceTypes[Math.floor(Math.random() * deviceTypes.length)];
    const vendor = vendors[Math.floor(Math.random() * vendors.length)];
    const rssi = -40 - Math.floor(Math.random() * 50);
    const isPaired = Math.random() > 0.6;
    
    const vulnerabilities = [];
    if (Math.random() > 0.7) {
      vulnerabilities.push("BlueBorne vulnerability detected");
    }
    if (!isPaired && Math.random() > 0.5) {
      vulnerabilities.push("Device in discoverable mode");
    }
    
    devices.push({
      name: `${vendor} ${deviceType}`,
      address: Array.from({length: 6}, () => 
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
      ).join(':').toUpperCase(),
      rssi,
      deviceType,
      paired: isPaired,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ["None detected"],
      version: `BLE ${Math.random() > 0.5 ? '5.0' : '4.2'}`
    });
  }
  
  return devices.sort((a, b) => b.rssi - a.rssi);
}

async function scanNFCTags() {
  const tags = [];
  const tagTypes = ["NTAG", "MIFARE Classic", "MIFARE Ultralight", "FeliCa", "ISO 14443"];
  
  const numTags = Math.floor(Math.random() * 4) + 1;
  
  for (let i = 0; i < numTags; i++) {
    const tagType = tagTypes[Math.floor(Math.random() * tagTypes.length)];
    const hasData = Math.random() > 0.3;
    
    const vulnerabilities = [];
    if (tagType === "MIFARE Classic") {
      vulnerabilities.push("Vulnerable to Darkside attack");
      vulnerabilities.push("Weak crypto implementation");
    }
    if (hasData) {
      vulnerabilities.push("Contains readable data");
    }
    
    tags.push({
      uid: Array.from({length: 7}, () => 
        Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
      ).join(':').toUpperCase(),
      type: tagType,
      data: hasData ? "Payment card / Access credential" : "Empty tag",
      readable: hasData,
      writable: Math.random() > 0.5,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ["None detected"],
      size: `${Math.floor(Math.random() * 512) + 64} bytes`
    });
  }
  
  return tags;
}

async function scanRFSignals() {
  const signals = [];
  const signalTypes = [
    { type: "WiFi 2.4GHz", freq: 2.4, band: "ISM" },
    { type: "WiFi 5GHz", freq: 5.0, band: "UNII" },
    { type: "Bluetooth", freq: 2.4, band: "ISM" },
    { type: "Cellular LTE", freq: 1.8, band: "Licensed" },
    { type: "Zigbee", freq: 2.4, band: "ISM" },
    { type: "LoRa", freq: 0.915, band: "ISM" }
  ];
  
  const numSignals = Math.floor(Math.random() * 8) + 5;
  
  for (let i = 0; i < numSignals; i++) {
    const signal = signalTypes[Math.floor(Math.random() * signalTypes.length)];
    const power = -50 - Math.floor(Math.random() * 60);
    
    const vulnerabilities = [];
    if (signal.band === "ISM") {
      vulnerabilities.push("Unlicensed band - prone to interference");
    }
    if (power > -60) {
      vulnerabilities.push("Strong signal - active transmission");
    }
    
    signals.push({
      type: signal.type,
      frequency: `${signal.freq} GHz`,
      bandwidth: `${Math.floor(Math.random() * 40) + 20} MHz`,
      power: `${power} dBm`,
      modulation: Math.random() > 0.5 ? "OFDM" : "DSSS",
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ["None detected"],
      active: Math.random() > 0.3
    });
  }
  
  return signals.sort((a, b) => parseFloat(b.power) - parseFloat(a.power));
}
