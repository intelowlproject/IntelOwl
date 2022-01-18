import React from "react";

import { useAuthStore, usePluginConfigurationStore } from "../../stores";
import initAxios from "../../utils/initAxios";

/**
 * Higher Order Component (HoC)
 */
const withAuth = (WrappedComponent) => (props) => {
  // stores
  const [isAuthenticated, fetchUserAccess] = useAuthStore(
    React.useCallback(
      (s) => [s.isAuthenticated(), s.service.fetchUserAccess],
      []
    )
  );

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
};

export default withAuth;
