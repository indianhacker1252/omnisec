import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Mic, MicOff, Volume2, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

// Web Speech API types
interface SpeechRecognitionEvent extends Event {
  results: SpeechRecognitionResultList;
}

interface SpeechRecognitionErrorEvent extends Event {
  error: string;
}

interface SpeechRecognitionInstance extends EventTarget {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start: () => void;
  stop: () => void;
  abort: () => void;
  onresult: ((event: SpeechRecognitionEvent) => void) | null;
  onerror: ((event: SpeechRecognitionErrorEvent) => void) | null;
  onend: (() => void) | null;
}

declare global {
  interface Window {
    SpeechRecognition?: new () => SpeechRecognitionInstance;
    webkitSpeechRecognition?: new () => SpeechRecognitionInstance;
  }
}

export const VoiceAssistant = () => {
  const { toast } = useToast();
  const [isListening, setIsListening] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState<{ role: string; text: string }[]>([]);
  const recognitionRef = useRef<SpeechRecognitionInstance | null>(null);
  const synthesisRef = useRef<SpeechSynthesisUtterance | null>(null);

  // Initialize speech recognition
  useEffect(() => {
    if ('SpeechRecognition' in window || 'webkitSpeechRecognition' in window) {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onresult = async (event) => {
        const text = event.results[0][0].transcript;
        console.log('Recognized:', text);
        setTranscript(prev => [...prev, { role: 'user', text }]);
        setIsListening(false);
        await processVoiceCommand(text);
      };

      recognitionRef.current.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        setIsListening(false);
        if (event.error !== 'no-speech') {
          toast({
            title: "Voice Error",
            description: `Recognition error: ${event.error}`,
            variant: "destructive",
          });
        }
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
      };
    }

    return () => {
      if (recognitionRef.current) {
        recognitionRef.current.abort();
      }
      window.speechSynthesis.cancel();
    };
  }, []);

  const processVoiceCommand = async (text: string) => {
    setIsProcessing(true);
    try {
      const { data, error } = await supabase.functions.invoke('voice-assistant', {
        body: { text, action: 'chat' }
      });

      if (error) throw error;

      const response = data.response || "I couldn't process that request.";
      setTranscript(prev => [...prev, { role: 'assistant', text: response }]);
      
      // Speak the response using browser's speech synthesis
      speakResponse(response);

    } catch (error: any) {
      console.error('Voice processing error:', error);
      const errorMsg = "Sorry, I encountered an error processing your request.";
      setTranscript(prev => [...prev, { role: 'assistant', text: errorMsg }]);
      speakResponse(errorMsg);
    } finally {
      setIsProcessing(false);
    }
  };

  const speakResponse = (text: string) => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 1.0;
      utterance.pitch = 1.0;
      utterance.volume = 1.0;
      
      // Try to use a good quality voice
      const voices = window.speechSynthesis.getVoices();
      const preferredVoice = voices.find(v => 
        v.name.includes('Google') || v.name.includes('Samantha') || v.name.includes('Daniel')
      ) || voices[0];
      
      if (preferredVoice) {
        utterance.voice = preferredVoice;
      }

      utterance.onstart = () => setIsSpeaking(true);
      utterance.onend = () => setIsSpeaking(false);
      utterance.onerror = () => setIsSpeaking(false);

      synthesisRef.current = utterance;
      window.speechSynthesis.speak(utterance);
    }
  };

  const startListening = () => {
    if (!recognitionRef.current) {
      toast({
        title: "Not Supported",
        description: "Speech recognition is not supported in this browser",
        variant: "destructive",
      });
      return;
    }

    // Stop any ongoing speech
    window.speechSynthesis.cancel();
    setIsSpeaking(false);

    try {
      recognitionRef.current.start();
      setIsListening(true);
      toast({
        title: "Listening...",
        description: "Speak your command",
      });
    } catch (e) {
      console.error('Failed to start recognition:', e);
    }
  };

  const stopListening = () => {
    if (recognitionRef.current) {
      recognitionRef.current.stop();
    }
    setIsListening(false);
  };

  const stopSpeaking = () => {
    window.speechSynthesis.cancel();
    setIsSpeaking(false);
  };

  return (
    <Card className="p-6 bg-card/50 backdrop-blur-sm border-cyber-purple/30">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Volume2 className="h-5 w-5 text-cyber-purple" />
          <h3 className="font-semibold font-mono">Voice Assistant</h3>
          <span className="text-xs text-muted-foreground">(Lovable AI)</span>
          {isSpeaking && (
            <div className="flex gap-1 ml-2">
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '0ms' }} />
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '150ms' }} />
              <div className="w-1 h-4 bg-cyber-purple animate-pulse" style={{ animationDelay: '300ms' }} />
            </div>
          )}
        </div>
        <div className="flex gap-2">
          {isSpeaking && (
            <Button onClick={stopSpeaking} variant="outline" size="sm">
              Stop
            </Button>
          )}
          {isListening ? (
            <Button onClick={stopListening} variant="destructive" size="sm" className="gap-2">
              <MicOff className="h-4 w-4" />
              Stop
            </Button>
          ) : (
            <Button 
              onClick={startListening} 
              className="gap-2 bg-cyber-purple hover:bg-cyber-purple/80"
              disabled={isProcessing}
            >
              {isProcessing ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  <Mic className="h-4 w-4" />
                  Speak
                </>
              )}
            </Button>
          )}
        </div>
      </div>

      {transcript.length > 0 && (
        <div className="mt-4 space-y-2 max-h-40 overflow-y-auto">
          {transcript.slice(-6).map((item, i) => (
            <div
              key={i}
              className={`text-sm font-mono p-2 rounded ${
                item.role === 'user' 
                  ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-2 border-cyber-cyan' 
                  : 'bg-cyber-purple/10 text-foreground border-l-2 border-cyber-purple'
              }`}
            >
              <span className="text-xs text-muted-foreground mr-2">
                {item.role === 'user' ? 'You:' : 'Jarvis:'}
              </span>
              {item.text}
            </div>
          ))}
        </div>
      )}

      {transcript.length === 0 && (
        <p className="text-sm text-muted-foreground text-center">
          Click "Speak" and say a command like "How do I scan for open ports?"
        </p>
      )}
    </Card>
  );
};