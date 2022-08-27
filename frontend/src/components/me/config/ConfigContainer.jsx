import React, { Suspense } from "react";
import PropTypes from "prop-types";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren } from "react-icons/ti";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";

const Parameters = React.lazy(() => import("./Parameters"));
const Secrets = React.lazy(() => import("./Secrets"));
const routes = (filterFunction, additionalConfigData) => [
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
        <Parameters
          filterFunction={filterFunction}
          additionalConfigData={additionalConfigData}
        />
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
        <Secrets
          filterFunction={filterFunction}
          additionalConfigData={additionalConfigData}
        />
      </Suspense>
    ),
  },
];

export default function ConfigContainer({
  filterFunction,
  additionalConfigData,
}) {
  console.debug("PluginsContainer rendered!");

  return <RouterTabs routes={routes(filterFunction, additionalConfigData)} />;
}

ConfigContainer.propTypes = {
  filterFunction: PropTypes.func,
  additionalConfigData: PropTypes.object,
};

ConfigContainer.defaultProps = {
  filterFunction: () => true,
  additionalConfigData: {},
};
