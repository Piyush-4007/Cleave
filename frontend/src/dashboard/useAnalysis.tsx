import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { getAnalysis, type Analysis } from "./api";

type State = { data: Analysis | null; loading: boolean; error: string | null };
const Ctx = createContext<State>({ data: null, loading: true, error: null });

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ data: null, loading: true, error: null });
  useEffect(() => {
    let alive = true;
    getAnalysis()
      .then((data) => alive && setState({ data, loading: false, error: null }))
      .catch((e) => alive && setState({ data: null, loading: false, error: String(e) }));
    return () => {
      alive = false;
    };
  }, []);
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export const useAnalysis = () => useContext(Ctx);
