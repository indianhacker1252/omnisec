import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

serve(async (req) => {
  const { headers } = req;
  const upgradeHeader = headers.get("upgrade") || "";

  if (upgradeHeader.toLowerCase() !== "websocket") {
    return new Response("Expected WebSocket connection", { status: 400 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  
  const OPENAI_API_KEY = Deno.env.get("OPENAI_API_KEY");
  if (!OPENAI_API_KEY) {
    console.error("OPENAI_API_KEY not configured");
    socket.close(1008, "API key not configured");
    return response;
  }

  console.log("Client connected to voice assistant");

  // Connect to OpenAI Realtime API
  const openAIUrl = "wss://api.openai.com/v1/realtime?model=gpt-4o-realtime-preview-2024-10-01";
  const openAISocket = new WebSocket(openAIUrl, {
    headers: {
      "Authorization": `Bearer ${OPENAI_API_KEY}`,
      "OpenAI-Beta": "realtime=v1"
    }
  });

  openAISocket.onopen = () => {
    console.log("Connected to OpenAI Realtime API");
  };

  openAISocket.onmessage = (event) => {
    // Forward OpenAI messages to client
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(event.data);
    }
  };

  openAISocket.onerror = (error) => {
    console.error("OpenAI WebSocket error:", error);
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: 'error',
        error: { message: 'OpenAI connection error' }
      }));
    }
  };

  openAISocket.onclose = () => {
    console.log("OpenAI connection closed");
    if (socket.readyState === WebSocket.OPEN) {
      socket.close();
    }
  };

  socket.onmessage = (event) => {
    // Forward client messages to OpenAI
    if (openAISocket.readyState === WebSocket.OPEN) {
      openAISocket.send(event.data);
    }
  };

  socket.onclose = () => {
    console.log("Client disconnected");
    if (openAISocket.readyState === WebSocket.OPEN) {
      openAISocket.close();
    }
  };

  socket.onerror = (error) => {
    console.error("Client WebSocket error:", error);
  };

  return response;
});
