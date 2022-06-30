import React, { Suspense } from "react";
import { FallBackLoading } from "@certego/certego-ui";

import AuthGuard from "../wrappers/AuthGuard";
import IfAuthRedirectGuard from "../wrappers/IfAuthRedirectGuard";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Organization = React.lazy(() => import("./me/organization/Organization"));
const Sessions = React.lazy(() => import("./me/sessions/Sessions"));
const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const JobResult = React.lazy(() => import("./jobs/result/JobResult"));
const PluginsContainer = React.lazy(() => import("./plugins/PluginsContainer"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const ScanForm = React.lazy(() => import("./scan/ScanForm"));

/*
lazy imports to enable code splitting
*/

// public components
const publicRoutesLazy = [
  {
    index: true,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Home />
      </Suspense>
    ),
  },
].map((r) => ({
  ...r,
  element: <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>,
}));

// no auth public components
const noAuthRoutesLazy = [
  {
    path: "/login",
    element: <Login />,
  },
].map((r) => ({
  ...r,
  element: (
    <IfAuthRedirectGuard>
      <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
    </IfAuthRedirectGuard>
  ),
}));

// auth components
const authRoutesLazy = [
  /* auth */
  {
    path: "/logout",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Logout />
      </Suspense>
    ),
  },
  /* User/Organization */
  {
    path: "/me/organization/*",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Organization />
      </Suspense>
    ),
  },
  /* API Access/Sessions Management */
  {
    path: "/me/sessions",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Sessions />
      </Suspense>
    ),
  },
  /* Jobs */
  {
    path: "/jobs",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <JobsTable />
      </Suspense>
    ),
  },
  {
    path: "/jobs/:id",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <JobResult />
      </Suspense>
    ),
  },
  /* Plugins */
  {
    path: "/plugins/*",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  /* Dashboard */
  {
    path: "/dashboard",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Dashboard />
      </Suspense>
    ),
  },
  /* Scan */
  {
    path: "/scan",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <ScanForm />
      </Suspense>
    ),
  },
].map((r) => ({
  ...r,
  element: (
    <AuthGuard>
      <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
    </AuthGuard>
  ),
}));

export { publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy };
