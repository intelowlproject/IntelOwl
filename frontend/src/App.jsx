import React from "react";
import { BrowserRouter } from "react-router-dom";
import { GuideProvider } from "./contexts/GuideContext";

// layout
import AppMain from "./layouts/AppMain";
import GuideWrapper from "./components/GuideWrapper";

function App() {
  return (
    <GuideProvider>
      <BrowserRouter>
        <GuideWrapper />
        <AppMain />
      </BrowserRouter>
    </GuideProvider>
  );
}

export default App;
