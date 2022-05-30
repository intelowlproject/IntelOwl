import React from "react";
import { BrowserRouter } from "react-router-dom";

// layout
import AppMain from "./layouts/AppMain";
import AppFooter from "./layouts/AppFooter";

function App() {
  return (
    <BrowserRouter>
      <AppMain />
      <AppFooter />
    </BrowserRouter>
  );
}

export default App;
