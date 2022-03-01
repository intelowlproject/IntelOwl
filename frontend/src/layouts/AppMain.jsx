import React from "react";
import { Route, Switch } from "react-router-dom";

// lib
import { FallBackLoading } from "@certego/certego-ui";

// wrapper
import AuthGuard from "../wrappers/AuthGuard";
import IfAuthRedirectGuard from "../wrappers/IfAuthRedirectGuard";
import withAuth from "../wrappers/withAuth";

// routes
import {
  publicRoutesLazy,
  noAuthRoutesLazy,
  authRoutesLazy
} from "../components/Routes";

function AppMain() {
  console.debug("AppMain rendered!");

  return (
    <React.Suspense fallback={<FallBackLoading />}>
      <Switch>
        {/* Public Routes */}
        {publicRoutesLazy.map((routeProps) => (
          <Route key={routeProps.path} {...routeProps} />
        ))}
        {/* No Auth Public Routes */}
        {noAuthRoutesLazy.map(({ component: Component, ...routeProps }) => (
          <Route
            key={routeProps.path}
            render={(props) => (
              <IfAuthRedirectGuard>
                <Component {...props} />
              </IfAuthRedirectGuard>
            )}
            {...routeProps}
          />
        ))}
        {/* Auth routes */}
        {authRoutesLazy.map(({ component: Component, ...routeProps }) => (
          <Route
            key={routeProps.path}
            render={(props) => (
              <AuthGuard>
                <Component {...props} />
              </AuthGuard>
            )}
            {...routeProps}
          />
        ))}
        {/* 404 */}
        <Route component={React.lazy(() => import("./NoMatch"))} />
      </Switch>
    </React.Suspense>
  );
}

export default withAuth(AppMain);
