import React from "react";

import { useAuthStore } from "../stores/useAuthStore";
import { usePluginConfigurationStore } from "../stores/usePluginConfigurationStore";

/**
 * Higher Order Component (HoC) -> https://reactjs.org/docs/higher-order-components.html
 * This pattern define a function that wraps a component and modify it adding props.
 *
 * In this specific case this function wraps all the main pages and check:
 * 1 - the user is authenticated
 * 2 - the plugins data have been downloaded
 */
function withAuth(WrappedComponent) {
  function AuthenticatedComponent(props) {
    // stores
    const [isAuthenticated, fetchUserAccess] = useAuthStore(
      React.useCallback(
        (state) => [state.isAuthenticated(), state.service.fetchUserAccess],
        [],
      ),
    );

    // check if the data about plugins have been downloaded or not.
    const [fetchPluginsConf] = usePluginConfigurationStore(
      React.useCallback((state) => [state.hydrate], []),
    );

    React.useEffect(() => {
      if (isAuthenticated) {
        fetchUserAccess();
        fetchPluginsConf();
      }
    }, [isAuthenticated, fetchUserAccess, fetchPluginsConf]); // onAuthStateChange

    return <WrappedComponent {...props} />;
  }
  return AuthenticatedComponent;
}

export default withAuth;
