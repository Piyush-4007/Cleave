import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Landing } from "./Landing";
import { DashboardShell } from "./dashboard/Shell";
import { Overview } from "./dashboard/Overview";
import { PathViewer } from "./dashboard/PathViewer";
import { Remediation } from "./dashboard/Remediation";
import { Findings, History } from "./dashboard/Simple";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<DashboardShell />}>
          <Route index element={<Overview />} />
          <Route path="paths" element={<PathViewer />} />
          <Route path="paths/:id" element={<PathViewer />} />
          <Route path="findings" element={<Findings />} />
          <Route path="remediation" element={<Remediation />} />
          <Route path="history" element={<History />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
