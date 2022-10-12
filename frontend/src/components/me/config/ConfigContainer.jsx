import React, { Suspense } from "react";
import PropTypes from "prop-types";
import { AiFillSetting } from "react-icons/ai";
import { GoGistSecret } from "react-icons/go";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";

const Parameters = React.lazy(() => import("./Parameters"));
const Secrets = React.lazy(() => import("./Secrets"));
const routes = (filterFunction, additionalConfigData, editable) => [
  {
    key: "plugins-parameters",
    location: "parameters",
    Title: () => (
      <span>
        <AiFillSetting />
        &nbsp;Parameters
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Parameters
          filterFunction={filterFunction}
          additionalConfigData={additionalConfigData}
          editable={editable}
        />
      </Suspense>
    ),
  },
  {
    key: "plugins-secrets",
    location: "secrets",
    Title: () => (
      <span>
        <GoGistSecret />
        &nbsp;Secrets
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Secrets
          filterFunction={filterFunction}
          additionalConfigData={additionalConfigData}
          editable={editable}
        />
      </Suspense>
    ),
  },
];

export default function ConfigContainer({
  filterFunction,
  additionalConfigData,
  editable,
}) {
  console.debug("PluginsContainer rendered!");

  return (
    <RouterTabs
      routes={routes(filterFunction, additionalConfigData, editable)}
    />
  );
}

ConfigContainer.propTypes = {
  filterFunction: PropTypes.func,
  additionalConfigData: PropTypes.object,
  editable: PropTypes.bool,
};

ConfigContainer.defaultProps = {
  filterFunction: () => true,
  additionalConfigData: {},
  editable: true,
};
