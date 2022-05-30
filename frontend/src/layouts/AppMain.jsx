import React, { Suspense } from "react";
import { useRoutes, Outlet } from "react-router-dom";
import PropTypes from "prop-types";
import { ErrorBoundary } from "react-error-boundary";
import { Row, Col } from "reactstrap";
import { FallBackLoading, ErrorAlert } from "@certego/certego-ui";

// wrapper
import withAuth from "../wrappers/withAuth";

// layout
import {
  publicRoutesLazy,
  noAuthRoutesLazy,
  authRoutesLazy,
} from "../components/Routes";
import AppHeader from "./AppHeader";

const NoMatch = React.lazy(() => import("./NoMatch"));

function ErrorHandler({ error }) {
  return (
    <Row>
      <Col>
        <ErrorAlert
          className="mt-5"
          error={{
            response: {
              statusText: "Something went wrong. Please reload browser.",
            },
            parsedMsg: error.message,
          }}
        />
      </Col>
    </Row>
  );
}

ErrorHandler.propTypes = {
  error: PropTypes.object.isRequired,
};

function Layout() {
  return (
    <>
      <AppHeader />
      <main role="main" className="px-1 px-md-5 mx-auto">
        <ErrorBoundary FallbackComponent={ErrorHandler}>
          <Outlet />
        </ErrorBoundary>
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
    },
    {
      path: "*",
      element: (
        <Suspense fallback={<FallBackLoading />}>
          <NoMatch />
        </Suspense>
      ),
    },
  ]);

  return routes;
}

export default AppMain;
