import React from "react";
import PropTypes from "prop-types";
import { Redirect } from "react-router-dom";
import useSearchParam from "react-use/lib/useSearchParam";

import { useAuthStore } from "../../stores";

/*
Wrapper for Routes which should be accesible only to a non-authenticated user
*/
export default function IfAuthRedirectGuard({ children, }) {
  // store
  const [loading, isAuthenticated] = useAuthStore(
    React.useCallback((s) => [s.loading, s.isAuthenticated()], [])
  );
  const next = useSearchParam("next") || "/";

  if (isAuthenticated && !loading) {
    return <Redirect replace to={next} />;
  }
  return children;
}

IfAuthRedirectGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
