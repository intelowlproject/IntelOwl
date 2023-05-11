/* eslint-disable react/prop-types */
import React from "react";
import PropTypes from "prop-types";
import { MdOutlineRefresh, MdPauseCircleOutline } from "react-icons/md";

import {
  NewJsonRenderer,
  DataTable,
  DefaultColumnFilter,
  IconButton,
  SelectOptionsFilter,
  DateHoverable,
} from "@certego/certego-ui";

import { StatusTag } from "../../../common";
import { PLUGIN_STATUSES } from "../../../../constants";
import { killPlugin, retryPlugin } from "../api";

const tableProps = {
  columns: [
    {
      Header: "Actions",
      id: "actions",
      accessor: (r) => r,
      maxWidth: 60,
      disableSortBy: true,
      Cell: ({ value: plugin, customProps: { job, refetch } }) => (
        <div className="d-flex-center">
          {job.permissions?.plugin_actions === true &&
            ["running", "pending"].includes(plugin.status.toLowerCase()) && (
              <IconButton
                id={`killplugin-${plugin.id}`}
                Icon={MdPauseCircleOutline}
                onClick={() => killPlugin(job.id, plugin).then(refetch)}
                color="accent"
                size="xs"
                title={`Kill ${plugin.type} run`}
                titlePlacement="top"
                className="me-2 border-0"
              />
            )}
          {job.permissions?.plugin_actions === true &&
            ["failed", "killed"].includes(plugin.status.toLowerCase()) && (
              <IconButton
                id={`retryplugin-${plugin.id}`}
                Icon={MdOutlineRefresh}
                onClick={() => retryPlugin(job.id, plugin).then(refetch)}
                color="light"
                size="xs"
                title={`Retry ${plugin.type} run`}
                titlePlacement="top"
                className="border-0"
              />
            )}
        </div>
      ),
    },
    {
      Header: "Status",
      id: "status",
      accessor: "status",
      Cell: ({ value }) => <StatusTag status={value} />,
      Filter: SelectOptionsFilter,
      selectOptions: PLUGIN_STATUSES,
      maxWidth: 50,
    },
    {
      Header: "Name",
      id: "name",
      accessor: "name",
      Filter: DefaultColumnFilter,
      maxWidth: 300,
    },
    {
      Header: "Process Time (s)",
      id: "process_time",
      accessor: "process_time",
      maxWidth: 75,
    },
    {
      Header: "Running Time",
      id: "running_time",
      accessor: (r) => r,
      disableSortBy: true,
      maxWidth: 125,
      Cell: ({ value: plugin }) => (
        <div>
          <DateHoverable noHover value={plugin?.start_time} format="pp" />
          &nbsp;<span className="fw-bold text-muted">-</span>&nbsp;
          <DateHoverable noHover value={plugin?.end_time} format="pp" />
          &nbsp;
          <DateHoverable noHover value={plugin?.end_time} format="(z)" />
        </div>
      ),
    },
  ],
  config: { enableExpanded: true, enableFlexLayout: true },
  initialState: {
    pageSize: 10,
    sortBy: [
      { id: "status", desc: true },
      { id: "name", desc: true },
    ],
  },
  SubComponent: ({ row }) => (
    <NewJsonRenderer
      collapsed={1}
      onEdit={() => null}
      key={row.id}
      id={`jobreport-jsoninput-${row.id}`}
      jsonData={{
        report: row.original?.report,
        errors: row.original?.errors,
        runtime_configuration: row.original?.runtime_configuration,
      }}
      style={{ height: "50vh", width: "90vw", overflow: "scroll" }}
    />
  ),
};

export function AnalyzersReportTable({ job, refetch }) {
  console.debug("AnalyzersReportTable rendered");
  return (
    <DataTable
      data={job?.analyzer_reports}
      customProps={{ job, refetch }}
      {...tableProps}
    />
  );
}

export function ConnectorsReportTable({ job, refetch }) {
  console.debug("ConnectorsReportTable rendered");
  return (
    <DataTable
      data={job?.connector_reports}
      customProps={{ job, refetch }}
      {...tableProps}
    />
  );
}

export function VisualizersReportTable({ job, refetch }) {
  console.debug("AnalyzersReportTable rendered");
  return (
    <DataTable
      data={job?.visualizer_reports}
      customProps={{ job, refetch }}
      {...tableProps}
    />
  );
}
AnalyzersReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};

ConnectorsReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};
VisualizersReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};
