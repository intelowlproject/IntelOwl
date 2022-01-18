import React from "react";

/*
lazy imports to enable code splitting
*/

// public components
const publicRoutesLazy = [
  {
    path: "/",
    exact: true,
    component: React.lazy(() => import("./Home/Home")),
  },
];

// no auth public components
const noAuthRoutesLazy = [
  {
    path: "/login",
    exact: true,
    component: React.lazy(() => import("./auth/public/Login")),
  },
];

// auth components
const authRoutesLazy = [
  /* auth */
  {
    path: "/logout",
    exact: true,
    component: React.lazy(() => import("./auth/public/Logout")),
  },
  /* User/Organization */
  {
    path: "/me/organization",
    exact: false,
    component: React.lazy(() => import("./me/organization/Organization")),
  },
  /* API Access/Sessions Management */
  {
    path: "/me/sessions",
    exact: true,
    component: React.lazy(() => import("./me/sessions/Sessions")),
  },
  /* Jobs */
  {
    path: "/jobs",
    exact: true,
    component: React.lazy(() => import("./jobs/JobsTable")),
  },
  {
    path: "/jobs/:id",
    exact: true,
    component: React.lazy(() => import("./jobs/JobResult")),
  },
  /* Plugins */
  {
    path: "/plugins",
    exact: false,
    component: React.lazy(() => import("./plugins/PluginsContainer")),
  },
  /* Dashboard */
  {
    path: "/dashboard",
    exact: true,
    component: React.lazy(() => import("./dashboard/Dashboard")),
  },
  /* Scan */
  {
    path: "/scan",
    exact: true,
    component: React.lazy(() => import("./scan/ScanForm")),
  },
];

export { publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy };
