import React from 'react';
import { useSetState } from 'react-use';
// eslint-disable-next-line no-unused-vars
import { Step } from 'react-joyride';

const GuideState = {
  run: false,
  stepIndex: 0,
  steps: [],
  tourActive: false,
};

export const GuideContext = React.createContext({
  state: GuideState,
  setState: () => undefined,
});
GuideContext.displayName = 'GuideContext';

export function GuideProvider(props) {
  const [state, setState] = useSetState(GuideState);

  const value = React.useMemo(
    () => ({
      state,
      setState,
    }),
    [setState, state],
  );

  return <GuideContext.Provider value={value} {...props} />;
}

export function useGuideContext(){
  const context = React.useContext(GuideContext);

  if (!context) {
    throw new Error('useGuideContext must be used within a GuideProvider');
  }

  return context;
}
