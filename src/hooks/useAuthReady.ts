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

    const recoverAuthState = async () => {
      clearStaleAuthStorage();
      await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);

      if (!mounted) return;
      setSession(null);
      setIsReady(true);
    };

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      const reason = event.reason as { message?: string; name?: string } | undefined;
      const message = reason?.message || "";
      const name = reason?.name || "";

      if (
        message.includes("Lock broken by another request with the 'steal' option") ||
        name.includes("AuthRetryableFetchError") ||
        message.includes("AuthRetryableFetchError") ||
        message.includes("Failed to fetch")
      ) {
        event.preventDefault();
        void recoverAuthState();
      }
    };

    window.addEventListener("unhandledrejection", handleUnhandledRejection);

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (!mounted) return;
      setSession(nextSession);
      setIsReady(true);
    });

    Promise.race([
      supabase.auth.getSession(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Auth init timeout")), AUTH_INIT_TIMEOUT_MS),
      ),
    ])
      .then((result) => {
        if (!mounted) return;
        const data = (result as { data?: { session?: Session | null } }).data;
        setSession(data?.session ?? null);
        setIsReady(true);
      })
      .catch(() => {
        void recoverAuthState();
      });

    return () => {
      mounted = false;
      window.removeEventListener("unhandledrejection", handleUnhandledRejection);
      subscription.unsubscribe();
    };
  }, []);

  return { session, isReady };
};
