import React from "react";

// react router
import { BrowserRouter } from "react-router-dom";

// layout
import AppHeader from "./components/layouts/AppHeader";
import AppMain from "./components/layouts/AppMain";
import AppFooter from "./components/layouts/AppFooter";

function App() {
  console.debug("App rendered!");

  return (
    <BrowserRouter>
      {/* Header */}
      <header className="fixed-top">
        <AppHeader />
      </header>
      {/* Main */}
      <main role="main" className="px-1 px-md-5 mx-auto">
        <AppMain />
      </main>
      {/* Footer */}
      <footer>
        <AppFooter />
      </footer>
    </BrowserRouter>
  );
}

export default App;
