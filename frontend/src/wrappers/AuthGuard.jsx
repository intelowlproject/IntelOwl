import React from "react";
import PropTypes from "prop-types";
import { Navigate, useLocation } from "react-router-dom";
import Cookies from "js-cookie";

import { FallBackLoading, addToast } from "@certego/certego-ui";

import { useAuthStore, CSRF_TOKEN } from "../stores/useAuthStore";

/*
Wrapper for Routes which should be accessible only to a authenticated user
*/
export default function AuthGuard({ children }) {
  // store
  const [loading, isAuthenticated, fetchUserAccess] = useAuthStore(
    React.useCallback(
      (state) => [
        state.loading,
        state.isAuthenticated(),
        state.service.fetchUserAccess,
      ],
      [],
    ),
  );

  const location = useLocation();
  const didJustLogout = location?.pathname.includes("logout");

  const [initialCheckDone, setInitialCheckDone] = React.useState(false);
  React.useEffect(() => {
    if (!isAuthenticated && Cookies.get(CSRF_TOKEN)) {
      fetchUserAccess().finally(() => setInitialCheckDone(true));
    } else {
      setInitialCheckDone(true);
    }
    // intentionally run only once on mount to restore session from cookie
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // side effects
  React.useEffect(() => {
    if (!didJustLogout && !isAuthenticated && !loading && initialCheckDone) {
      addToast("Login required to access the requested page.", null, "info");
    }
  }, [didJustLogout, isAuthenticated, loading, initialCheckDone]);

  if (loading || !initialCheckDone) {
    return <FallBackLoading />;
  }

  if (!isAuthenticated && !loading) {
    return (
      <Navigate
        to={{
          pathname: didJustLogout ? "/" : "/login",
          search: didJustLogout ? undefined : `?next=${location.pathname}`,
        }}
      />
    );
  }

  return children;
}

AuthGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
