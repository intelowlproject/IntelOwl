/* eslint-disable react/prop-types */
import React from "react";
import { UncontrolledTooltip } from "reactstrap";

import { DateHoverable } from "@certego/certego-ui";

import { JobResultSections } from "../../constants/miscConst";
import { StatusTag } from "../common/StatusTag";
import { TableCellCollapse } from "../common/TableCellCollapse";

export const searchTableColumns = [
  {
    Header: "Job ID",
    id: "job_id",
    accessor: "job.id",
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center">
        <a
          id={`job-${id}`}
          href={`/jobs/${id}/${JobResultSections.VISUALIZER}`}
          target="_blank"
          rel="noreferrer"
        >
          #{id}
        </a>
        <UncontrolledTooltip target={`job-${id}`} placement="top" fade={false}>
          View Job Report
        </UncontrolledTooltip>
      </div>
    ),
    disableSortBy: true,
    maxWidth: 60,
  },
  {
    Header: "Start time",
    id: "start_time",
    accessor: "start_time",
    Cell: ({ value }) => (
      <DateHoverable value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    disableSortBy: true,
    maxWidth: 120,
  },
  {
    Header: "End time",
    id: "end_time",
    accessor: "end_time",
    Cell: ({ value }) => (
      <DateHoverable value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    disableSortBy: true,
    maxWidth: 120,
  },
  {
    Header: "Type",
    id: "type",
    accessor: "config.plugin_name",
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    Header: "Name",
    id: "name",
    accessor: "config.name",
    disableSortBy: true,
  },
  {
    Header: "Status",
    id: "status",
    accessor: "status",
    Cell: ({ value }) => <StatusTag status={value} className="py-0" />,
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    Header: "Errors",
    id: "errors",
    accessor: "errors",
    Cell: ({ value }) => <TableCellCollapse values={value} label="errors" />,
    disableSortBy: true,
    maxWidth: 90,
  },
];
