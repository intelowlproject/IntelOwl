import React, { Suspense } from "react";
import { FallBackLoading } from "@certego/certego-ui";
import { Navigate, useParams } from "react-router-dom";

import AuthGuard from "../wrappers/AuthGuard";
import IfAuthRedirectGuard from "../wrappers/IfAuthRedirectGuard";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Register = React.lazy(() => import("./auth/Register"));
const EmailVerification = React.lazy(() => import("./auth/EmailVerification"));
const ResetPassword = React.lazy(() => import("./auth/ResetPassword"));
const Organization = React.lazy(() => import("./organization/Organization"));
const Sessions = React.lazy(() => import("./user/sessions/Sessions"));
const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const JobResult = React.lazy(() => import("./jobs/result/JobResult"));
const CommentResult = React.lazy(() =>
  import("./jobs/result/bar/comment/CommentResult"),
);
const PluginsContainer = React.lazy(() => import("./plugins/PluginsContainer"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const ScanForm = React.lazy(() => import("./scan/ScanForm"));
const UserConfig = React.lazy(() => import("./user/config/UserConfig"));
const ChangePassword = React.lazy(() => import("./auth/ChangePassword"));
/*
lazy imports to enable code splitting
*/

function JobRedirect() {
  const params = useParams();
  const { id } = params;
  return <Navigate to={`/jobs/${id}/visualizer`} replace />;
}

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
  {
    path: "/register",
    element: <Register />,
  },
  {
    path: "/verify-email",
    element: <EmailVerification />,
  },
  {
    path: "/reset-password",
    element: <ResetPassword />,
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

  {
    path: "/change-password",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <ChangePassword />
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
  /* CustomConfig */
  {
    path: "/me/config/*",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <UserConfig />
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
  // this is needed for retrocompatibility
  {
    path: `/jobs/:id`,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <JobRedirect />
      </Suspense>
    ),
  },
  // this is needed from start scan: we don't know visualizers before enter in the job
  {
    path: `/jobs/:id/:section`,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <JobResult />
      </Suspense>
    ),
  },
  {
    /*
      ex: jobs/1/visualizer/DNS
      ex: jobs/1/raw/analyzers
    */
    path: `/jobs/:id/:section/:subSection`,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <JobResult />
      </Suspense>
    ),
  },
  {
    path: "/jobs/:id/comments",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <CommentResult />
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
