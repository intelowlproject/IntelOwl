import React, { Suspense } from "react";
import { FallBackLoading } from "@certego/certego-ui";
import { Navigate, useParams } from "react-router-dom";

import { fromZonedTime } from "date-fns-tz";
import AuthGuard from "../wrappers/AuthGuard";
import IfAuthRedirectGuard from "../wrappers/IfAuthRedirectGuard";
import { JobResultSections, localTimezone } from "../constants/miscConst";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Register = React.lazy(() => import("./auth/Register"));
const EmailVerification = React.lazy(() => import("./auth/EmailVerification"));
const ResetPassword = React.lazy(() => import("./auth/ResetPassword"));
const Organization = React.lazy(() => import("./organization/Organization"));
const TokenPage = React.lazy(() => import("./user/token/TokenPage"));
const JobResult = React.lazy(() => import("./jobs/result/JobResult"));
const CommentResult = React.lazy(
  () => import("./jobs/result/bar/comment/CommentResult"),
);
const PluginsContainer = React.lazy(() => import("./plugins/PluginsContainer"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const ScanForm = React.lazy(() => import("./scan/ScanForm"));
const ChangePassword = React.lazy(() => import("./auth/ChangePassword"));
const InvestigationResult = React.lazy(
  () => import("./investigations/result/InvestigationResult"),
);
const History = React.lazy(() => import("./history/History"));
const ReportsSearch = React.lazy(() => import("./search/ReportsSearch"));
const Analyzables = React.lazy(() => import("./analyzables/Analyzables"));
const AnalyzableResult = React.lazy(
  () => import("./analyzables/result/AnalyzableResult"),
);

function CustomRedirect() {
  /* this is a way to auto-redirect to the job page with the current date:
   * we cannot use a button -> change the UI
   * we cannot use a navigate -> "to" props must have a string (no function) and if we worte new Date in the to url the components is generated once so the first date is keep
   */
  const [endDatetime, forceUpdate] = React.useState(new Date());

  React.useEffect(() => {
    forceUpdate(new Date());
  }, []);

  const startDatetime = structuredClone(endDatetime);
  startDatetime.setDate(startDatetime.getDate() - 7);

  return (
    <Navigate
      to={`/history/jobs?received_request_time__gte=${encodeURIComponent(
        fromZonedTime(startDatetime, localTimezone).toISOString(),
      )}&received_request_time__lte=${encodeURIComponent(
        fromZonedTime(endDatetime, localTimezone).toISOString(),
      )}&ordering=-received_request_time`}
      replace
    />
  );
}

/*
lazy imports to enable code splitting
*/

function JobRedirect() {
  const params = useParams();
  const { id } = params;
  return (
    <Navigate to={`/jobs/${id}/${JobResultSections.VISUALIZER}`} replace />
  );
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
].map((routes) => ({
  ...routes,
  element: <Suspense fallback={<FallBackLoading />}>{routes.element}</Suspense>,
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
].map((routes) => ({
  ...routes,
  element: (
    <IfAuthRedirectGuard>
      <Suspense fallback={<FallBackLoading />}>{routes.element}</Suspense>
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
  /* API Access */
  {
    path: "/me/api",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <TokenPage />
      </Suspense>
    ),
  },
  /* Jobs */
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
  {
    path: "/history",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <CustomRedirect />
      </Suspense>
    ),
  },
  {
    path: "/history/jobs",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <History />
      </Suspense>
    ),
  },
  {
    path: "/history/investigations",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <History />
      </Suspense>
    ),
  },
  {
    path: "/history/user-events",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <History />
      </Suspense>
    ),
  },
  {
    path: "/history/user-domain-wildcard-events",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <History />
      </Suspense>
    ),
  },
  {
    path: "/history/user-ip-wildcard-events",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <History />
      </Suspense>
    ),
  },
  /* Investigation */
  {
    path: `/investigation/:id`,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <InvestigationResult />
      </Suspense>
    ),
  },
  /* Plugins */
  {
    path: "/plugins",
    element: <Navigate to="/plugins/analyzers" replace />,
  },
  {
    path: "/plugins/analyzers",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  {
    path: "/plugins/connectors",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  {
    path: "/plugins/pivots",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  {
    path: "/plugins/visualizers",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  {
    path: "/plugins/ingestors",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <PluginsContainer />
      </Suspense>
    ),
  },
  {
    path: "/plugins/playbooks",
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
  /* Search */
  {
    path: "/search",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <ReportsSearch />
      </Suspense>
    ),
  },
  /* Analyzables */
  {
    path: "/artifacts",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Analyzables />
      </Suspense>
    ),
  },
  {
    path: `/artifacts/:id`,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <AnalyzableResult />
      </Suspense>
    ),
  },
].map((routes) => ({
  ...routes,
  element: (
    <AuthGuard>
      <Suspense fallback={<FallBackLoading />}>{routes.element}</Suspense>
    </AuthGuard>
  ),
}));

export { publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy };
