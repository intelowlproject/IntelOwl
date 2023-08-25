import React from "react";
import { useSetState } from "react-use";

const GuideState = {
  run: false,
  stepIndex: 0,
  steps: [],
  tourActive: false,
};

export const GuideContext = React.createContext({
  guideState: GuideState,
  setGuideState: () => undefined,
});
GuideContext.displayName = "GuideContext";

export function GuideProvider(props) {
  const [guideState, setGuideState] = useSetState(GuideState);

  const value = React.useMemo(
    () => ({
      guideState,
      setGuideState,
    }),
    [setGuideState, guideState],
  );

  return <GuideContext.Provider value={value} {...props} />;
}

export function useGuideContext() {
  const context = React.useContext(GuideContext);

  if (!context) {
    throw new Error("useGuideContext must be used within a GuideProvider");
  }

  return context;
}
