import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { DESKTOP } from "./desktop";
import { Landing } from "./Landing";
import { DashboardShell } from "./dashboard/Shell";
import { Overview } from "./dashboard/Overview";
import { PathViewer } from "./dashboard/PathViewer";
import { Remediation } from "./dashboard/Remediation";
import { Findings, History } from "./dashboard/Simple";
import { Connect } from "./dashboard/Connect";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* The desktop app is the tool, not the marketing site: open straight on it. */}
        <Route path="/" element={DESKTOP ? <Navigate to="/dashboard" replace /> : <Landing />} />
        <Route path="/dashboard" element={<DashboardShell />}>
          <Route index element={<Overview />} />
          <Route path="paths" element={<PathViewer />} />
          <Route path="paths/:id" element={<PathViewer />} />
          <Route path="findings" element={<Findings />} />
          <Route path="remediation" element={<Remediation />} />
          <Route path="history" element={<History />} />
          <Route path="connect" element={<Connect />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
