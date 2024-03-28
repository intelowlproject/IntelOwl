// import "./wdyr";

import "./styles/App.scss";

import React from "react";
import ReactDOM from "react-dom";
import App from "./App";
import * as serviceWorker from "./serviceWorker";

import initAxios from "./utils/initAxios";

function noop() {}
// hack to disable console.debug statements in production build
if (process.env.NODE_ENV !== "development") {
  console.debug = noop;
}

initAxios();

ReactDOM.render(<App />, document.getElementById("root"));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
