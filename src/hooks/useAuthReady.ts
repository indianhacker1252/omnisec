import { useEffect, useState } from "react";
import { Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";

const AUTH_INIT_TIMEOUT_MS = 5000;

const clearStaleAuthStorage = () => {
  try {
    const keys = Object.keys(localStorage).filter(
      (key) => key.startsWith("sb-") && key.includes("auth-token"),
    );

    keys.forEach((key) => localStorage.removeItem(key));
  } catch {
    // Ignore storage access issues
  }
};

export const useAuthReady = () => {
  const [session, setSession] = useState<Session | null>(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    let mounted = true;

    const applySessionState = (nextSession: Session | null) => {
      if (!mounted) return;
      setSession(nextSession);
      setIsReady(true);

      if (nextSession) {
        supabase.auth.startAutoRefresh();
      } else {
        supabase.auth.stopAutoRefresh();
      }
    };

    const initializeAuth = async () => {
      try {
        const result = (await Promise.race([
          supabase.auth.getSession(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("Auth init timeout")), AUTH_INIT_TIMEOUT_MS),
          ),
        ])) as { data?: { session?: Session | null } };

        applySessionState(result.data?.session ?? null);
      } catch {
        clearStaleAuthStorage();
        await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
        applySessionState(null);
      }

      const {
        data: { subscription },
      } = supabase.auth.onAuthStateChange((_event, nextSession) => {
        applySessionState(nextSession);
      });

      if (!mounted) {
        subscription.unsubscribe();
      }

      return subscription;
    };

    let authSubscription: { unsubscribe: () => void } | null = null;

    void initializeAuth().then((subscription) => {
      authSubscription = subscription;
    });

    return () => {
      mounted = false;
      authSubscription?.unsubscribe();
    };
  }, []);

  return { session, isReady };
};
