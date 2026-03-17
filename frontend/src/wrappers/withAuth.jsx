import React from "react";

import { useAuthStore } from "../stores/useAuthStore";

/**
 * Higher Order Component (HoC) -> https://reactjs.org/docs/higher-order-components.html
 * This pattern define a function that wraps a component and modify it adding props.
 *
 * In this specific case this function wraps all the main pages and check:
 * 1 - the user is authenticated
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

    React.useEffect(() => {
      if (isAuthenticated) {
        fetchUserAccess();
      }
    }, [isAuthenticated, fetchUserAccess]);

    return <WrappedComponent {...props} />;
  }
  return AuthenticatedComponent;
}

export default withAuth;
