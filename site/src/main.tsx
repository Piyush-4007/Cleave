import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MotionConfig } from "framer-motion";
import App from "./App";
import { AuthProvider } from "./lib/auth";
import { GetCleaveProvider } from "./components/GetCleave";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MotionConfig reducedMotion="user">
      <AuthProvider>
        <GetCleaveProvider>
          <App />
        </GetCleaveProvider>
      </AuthProvider>
    </MotionConfig>
  </StrictMode>,
);
