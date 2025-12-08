import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Mic, Phone, PhoneOff, AlertCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { AudioRecorder, encodeAudioForAPI, playAudioData } from "@/utils/VoiceAssistant";

export const VoiceAssistant = () => {
  const { toast } = useToast();
  const [isConnected, setIsConnected] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [isConfigured, setIsConfigured] = useState<boolean | null>(null);
  const [transcript, setTranscript] = useState<string[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const recorderRef = useRef<AudioRecorder | null>(null);

  const PROJECT_REF = import.meta.env.VITE_SUPABASE_URL?.split('//')[1]?.split('.')[0];

  // Check if voice assistant is configured
  useEffect(() => {
    const checkConfig = async () => {
      try {
        const wsUrl = `wss://${PROJECT_REF}.supabase.co/functions/v1/voice-assistant`;
        const testWs = new WebSocket(wsUrl);
        
        testWs.onopen = () => {
          // Connection succeeded, but we'll get a close message if API key is missing
        };
        
        testWs.onclose = (event) => {
          if (event.code === 1008) {
            // API key not configured
            setIsConfigured(false);
          } else if (event.code !== 1000) {
            setIsConfigured(false);
          }
          testWs.close();
        };
        
        testWs.onerror = () => {
          setIsConfigured(false);
        };
        
        // If we don't get a close within 2 seconds, assume it's working
        setTimeout(() => {
          if (isConfigured === null) {
            setIsConfigured(true);
          }
          if (testWs.readyState === WebSocket.OPEN) {
            testWs.close();
          }
        }, 2000);
      } catch {
        setIsConfigured(false);
      }
    };
    
    checkConfig();
  }, [PROJECT_REF]);

  const startVoiceChat = async () => {
    if (!isConfigured) {
      toast({
        title: "Voice Assistant Not Configured",
        description: "OpenAI API key is required. Please configure it in project secrets.",
        variant: "destructive",
      });
      return;
    }

    try {
      await navigator.mediaDevices.getUserMedia({ audio: true });
      audioContextRef.current = new AudioContext({ sampleRate: 24000 });

      const wsUrl = `wss://${PROJECT_REF}.supabase.co/functions/v1/voice-assistant`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('Voice assistant connected');
        setIsConnected(true);
        toast({
          title: "Voice Assistant Connected",
          description: "Speak naturally to interact with OmniSec AI",
        });
      };

      ws.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log('Received:', data.type);

          if (data.type === 'session.created') {
            ws.send(JSON.stringify({
              type: 'session.update',
              session: {
                modalities: ['text', 'audio'],
                instructions: `You are OmniSec Voice Assistant, an elite cybersecurity AI expert specializing in:
- Network security and penetration testing
- Vulnerability assessment and exploitation guidance
- Security tool usage (Nmap, Metasploit, Burp Suite)
- Threat analysis and incident response
- OWASP Top 10 vulnerabilities
- Real-time security operations guidance

Provide concise, actionable security advice. When asked about scanning or attacks, explain tools and techniques clearly. Always emphasize authorized testing only.`,
                voice: 'alloy',
                input_audio_format: 'pcm16',
                output_audio_format: 'pcm16',
                input_audio_transcription: { model: 'whisper-1' },
                turn_detection: {
                  type: 'server_vad',
                  threshold: 0.5,
                  prefix_padding_ms: 300,
                  silence_duration_ms: 1000
                },
                temperature: 0.8,
                max_response_output_tokens: 4096
              }
            }));

            recorderRef.current = new AudioRecorder((audioData) => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  type: 'input_audio_buffer.append',
                  audio: encodeAudioForAPI(audioData)
                }));
              }
            });
            await recorderRef.current.start();
          } else if (data.type === 'response.audio.delta') {
            setIsSpeaking(true);
            const binaryString = atob(data.delta);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
              bytes[i] = binaryString.charCodeAt(i);
            }
            if (audioContextRef.current) {
              await playAudioData(audioContextRef.current, bytes);
            }
          } else if (data.type === 'response.audio.done') {
            setIsSpeaking(false);
          } else if (data.type === 'conversation.item.input_audio_transcription.completed') {
            setTranscript(prev => [...prev, `You: ${data.transcript}`]);
          } else if (data.type === 'response.audio_transcript.delta') {
            setTranscript(prev => {
              const lastIndex = prev.length - 1;
              if (prev[lastIndex]?.startsWith('Assistant:')) {
                return [...prev.slice(0, -1), prev[lastIndex] + data.delta];
              }
              return [...prev, `Assistant: ${data.delta}`];
            });
          } else if (data.type === 'error') {
            console.error('WebSocket error:', data.error);
            toast({
              title: "Voice Error",
              description: data.error.message || "An error occurred",
              variant: "destructive",
            });
          }
        } catch (error) {
          console.error('Message parsing error:', error);
        }
      };

      ws.onerror = () => {
        toast({
          title: "Connection Error",
          description: "Failed to connect to voice assistant",
          variant: "destructive",
        });
      };

      ws.onclose = () => {
        setIsConnected(false);
        setIsSpeaking(false);
      };

    } catch (error) {
      console.error('Failed to start voice chat:', error);
      toast({
        title: "Microphone Error",
        description: "Please allow microphone access to use voice assistant",
        variant: "destructive",
      });
    }
  };

  const stopVoiceChat = () => {
    recorderRef.current?.stop();
    wsRef.current?.close();
    audioContextRef.current?.close();
    setIsConnected(false);
    setIsSpeaking(false);
  };

  useEffect(() => {
    return () => {
      stopVoiceChat();
    };
  }, []);

  // Show configuration required message
  if (isConfigured === false) {
    return (
      <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
        <div className="flex items-center gap-2 mb-4">
          <Phone className="h-5 w-5 text-cyber-purple" />
          <h3 className="font-semibold font-mono">Voice Assistant</h3>
        </div>
        <div className="flex items-center gap-3 p-4 bg-warning/10 border border-warning/30 rounded-lg">
          <AlertCircle className="h-5 w-5 text-warning flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-warning">Configuration Required</p>
            <p className="text-xs text-muted-foreground mt-1">
              Add OPENAI_API_KEY in project secrets to enable voice assistant
            </p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Phone className="h-5 w-5 text-cyber-purple" />
          <h3 className="font-semibold font-mono">Voice Assistant</h3>
          {isSpeaking && (
            <div className="flex gap-1">
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '0ms' }} />
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '150ms' }} />
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '300ms' }} />
            </div>
          )}
        </div>
        {isConnected ? (
          <Button onClick={stopVoiceChat} variant="destructive" size="sm" className="gap-2">
            <PhoneOff className="h-4 w-4" />
            Disconnect
          </Button>
        ) : (
          <Button 
            onClick={startVoiceChat} 
            className="gap-2 bg-cyber-purple hover:bg-cyber-purple/80"
            disabled={isConfigured === null}
          >
            <Mic className="h-4 w-4" />
            {isConfigured === null ? "Checking..." : "Start Voice Chat"}
          </Button>
        )}
      </div>

      {transcript.length > 0 && (
        <div className="mt-4 space-y-2 max-h-60 overflow-y-auto">
          {transcript.map((text, i) => (
            <div
              key={i}
              className={`text-sm font-mono ${
                text.startsWith('You:') ? 'text-cyber-cyan' : 'text-cyber-purple'
              }`}
            >
              {text}
            </div>
          ))}
        </div>
      )}

      {!isConnected && transcript.length === 0 && (
        <p className="text-sm text-muted-foreground text-center">
          Click "Start Voice Chat" to interact with Jarvis-like AI assistant
        </p>
      )}
    </Card>
  );
};
