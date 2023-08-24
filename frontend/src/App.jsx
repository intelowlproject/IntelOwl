import React from "react";
import { BrowserRouter } from "react-router-dom";
import { GuideProvider } from "./contexts/GuideContext";

// layout
import AppMain from "./layouts/AppMain";
import AppFooter from "./layouts/AppFooter";
import GuideWrapper from "./components/misc/GuideWrapper";

function App() {
  return (
    <GuideProvider>
      <BrowserRouter>
        <GuideWrapper />
        <AppMain />
        <AppFooter />
      </BrowserRouter>
    </GuideProvider>
  );
}

export default App;
