import React, { Suspense } from "react";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren } from "react-icons/ti";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";

const Parameters = React.lazy(() => import("./Parameters"));
const Secrets = React.lazy(() => import("./Secrets"));
const routes = [
  {
    key: "plugins-parameters",
    location: "parameters",
    Title: () => (
      <span>
        <AiOutlineApi />
        &nbsp;Parameters
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Parameters />
      </Suspense>
    ),
  },
  {
    key: "plugins-secrets",
    location: "secrets",
    Title: () => (
      <span>
        <TiFlowChildren />
        &nbsp;Secrets
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Secrets />
      </Suspense>
    ),
  },
];

export default function ConfigContainer() {
  console.debug("PluginsContainer rendered!");

  return <RouterTabs routes={routes} />;
}
