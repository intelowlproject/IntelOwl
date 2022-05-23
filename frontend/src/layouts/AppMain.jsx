import React, { Suspense } from "react";
import { useRoutes, Outlet } from "react-router-dom";
import { FallBackLoading } from "@certego/certego-ui";

// wrapper
import withAuth from "../wrappers/withAuth";

// layout
import {publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy } from "../components/Routes";
import AppHeader from "./AppHeader";

const NoMatch = React.lazy(() => import("./NoMatch"));

function Layout() {
  return (
    <>
      <AppHeader />
      <main role="main" className="px-1 px-md-5 mx-auto">
        <Outlet />
      </main>
    </>
  );
}

function AppMain() {
  const AuthLayout = withAuth(Layout);
  const routes = useRoutes([
    {
      path: "/",
      element: <AuthLayout />,
      children: [...publicRoutesLazy, ...noAuthRoutesLazy, ...authRoutesLazy],
    }, {
      path: "*",
      element:
        <Suspense fallback={<FallBackLoading />}>
          <NoMatch />
        </Suspense>,
    },
  ]);

  return routes;
}

export default AppMain;
