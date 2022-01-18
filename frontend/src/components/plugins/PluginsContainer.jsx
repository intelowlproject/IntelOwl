import React from "react";
import PropTypes from "prop-types";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren } from "react-icons/ti";

import { RouterTabs } from "@certego/certego-ui";

export default function PluginsContainer({ match, }) {
  console.debug("PluginsContainer rendered!");

  const routes = React.useMemo(
    () => [
      {
        key: "plugins-analyzers",
        location: { pathname: `${match.url}/analyzers`, },
        Title: () => (
          <span>
            <AiOutlineApi />
            &nbsp;Analyzers
          </span>
        ),
        Component: React.lazy(() => import("./utils/Analyzers")),
      },
      {
        key: "plugins-connectors",
        location: { pathname: `${match.url}/connectors`, },
        Title: () => (
          <span>
            <TiFlowChildren />
            &nbsp;Connectors
          </span>
        ),
        Component: React.lazy(() => import("./utils/Connectors")),
      },
    ],
    [match.url]
  );

  return <RouterTabs routes={routes} />;
}

PluginsContainer.propTypes = {
  match: PropTypes.shape({
    url: PropTypes.string.isRequired,
  }).isRequired,
};
