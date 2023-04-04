import React from "react";

import { useAuthStore, usePluginConfigurationStore } from "../stores";
import initAxios from "../utils/initAxios";

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
        (s) => [s.isAuthenticated(), s.service.fetchUserAccess],
        []
      )
    );

    // check if the data about plugins have been downloaded or not.
    const [fetchPluginsConf] = usePluginConfigurationStore(
      React.useCallback((s) => [s.hydrate], [])
    );

    React.useLayoutEffect(() => {
      initAxios();
    }, []); // axios req & resp interceptor

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
