import React from "react";
import PropTypes from "prop-types";
import { Navigate } from "react-router-dom";
import useSearchParam from "react-use/lib/useSearchParam";

import { useAuthStore } from "../stores/useAuthStore";

/*
Wrapper for Routes which should be accessible only to a non-authenticated user
*/
export default function IfAuthRedirectGuard({ children }) {
  // store
  const [loading, isAuthenticated] = useAuthStore(
    React.useCallback((state) => [state.loading, state.isAuthenticated()], []),
  );
  const next = useSearchParam("next") || "/";

  if (isAuthenticated && !loading) {
    return <Navigate replace to={next} />;
  }
  return children;
}

IfAuthRedirectGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
