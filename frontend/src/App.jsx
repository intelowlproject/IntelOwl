import React from "react";

// react router
import { BrowserRouter } from "react-router-dom";

// layout
import AppHeader from "./layouts/AppHeader";
import AppMain from "./layouts/AppMain";
import AppFooter from "./layouts/AppFooter";

function App() {
  console.debug("App rendered!");

  const basename = document.querySelector("base")?.getAttribute("href") ?? "/"

  return (
    <BrowserRouter basename={basename}>
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
