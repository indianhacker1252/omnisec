import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason as { message?: string; name?: string } | undefined;
  const message = reason?.message || "";
  const name = reason?.name || "";

  if (
    message.includes("Lock broken by another request with the 'steal' option") ||
    name.includes("AuthRetryableFetchError") ||
    message.includes("AuthRetryableFetchError")
  ) {
    event.preventDefault();
    console.warn("Recovered auth lock/fetch rejection:", message || name);
  }
});

createRoot(document.getElementById("root")!).render(<App />);
