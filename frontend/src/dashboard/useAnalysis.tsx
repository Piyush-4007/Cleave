import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from "react";
import { getAnalysis, type Analysis } from "./api";

type State = { data: Analysis | null; loading: boolean; error: string | null; reload: () => void };
const Ctx = createContext<State>({ data: null, loading: true, error: null, reload: () => {} });

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<Omit<State, "reload">>({ data: null, loading: true, error: null });

  const reload = useCallback(() => {
    setState((s) => ({ ...s, loading: true }));
    getAnalysis()
      .then((data) => setState({ data, loading: false, error: null }))
      .catch((e) => setState({ data: null, loading: false, error: String(e) }));
  }, []);

  useEffect(() => { reload(); }, [reload]);

  return <Ctx.Provider value={{ ...state, reload }}>{children}</Ctx.Provider>;
}

export const useAnalysis = () => useContext(Ctx);
