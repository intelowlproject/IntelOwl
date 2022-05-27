import React, { Suspense } from "react";
import PropTypes from "prop-types";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren } from "react-icons/ti";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";

const Analyzers = React.lazy(() => import("./utils/Analyzers"));
const Connectors = React.lazy(() => import("./utils/Connectors"));

const routes = [
  {
    key: "plugins-analyzers",
    location: "analyzers",
    Title: () => (
      <span>
        <AiOutlineApi />&nbsp;Analyzers
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Analyzers />
      </Suspense>
    ),
  },
  {
    key: "plugins-connectors",
    location: "connectors",
    Title: () => (
      <span>
        <TiFlowChildren />&nbsp;Connectors
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Connectors />
      </Suspense>
    ),
  },
];

export default function PluginsContainer() {
  console.debug("PluginsContainer rendered!");

  return <RouterTabs routes={routes} />;
}

