/* eslint-disable react/prop-types */
import React from "react";
import PropTypes from "prop-types";
import { MdOutlineRefresh, MdPauseCircleOutline } from "react-icons/md";
import { JSONTree } from "react-json-tree";

import {
  DataTable,
  DefaultColumnFilter,
  IconButton,
  SelectOptionsFilter,
  DateHoverable,
} from "@certego/certego-ui";

import { StatusTag } from "../../common/StatusTag";
import { killPlugin, retryPlugin } from "./jobApi";
import { PluginStatuses } from "../../../constants/pluginConst";

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
      selectOptions: Object.values(PluginStatuses),
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
    <div
      id={`jobreport-jsoninput-${row.id}`}
      style={{ maxHeight: "50vh", overflow: "scroll" }}
    >
      <JSONTree
        data={{
          report: row.original?.report,
          errors: row.original?.errors,
          parameters: row.original?.parameters,
        }}
      />
    </div>
  ),
};

export function AnalyzersReportTable({ job, refetch }) {
  console.debug("AnalyzersReportTable rendered");
  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={job?.analyzer_reports}
        customProps={{ job, refetch }}
        {...tableProps}
      />
    </div>
  );
}

export function ConnectorsReportTable({ job, refetch }) {
  console.debug("ConnectorsReportTable rendered");
  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={job?.connector_reports}
        customProps={{ job, refetch }}
        {...tableProps}
      />
    </div>
  );
}
export function PivotsReportTable({ job, refetch }) {
  console.debug("ConnectorsReportTable rendered");
  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={job?.pivot_reports}
        customProps={{ job, refetch }}
        {...tableProps}
      />
    </div>
  );
}
export function VisualizersReportTable({ job, refetch }) {
  console.debug("AnalyzersReportTable rendered");
  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={job?.visualizer_reports}
        customProps={{ job, refetch }}
        {...tableProps}
      />
    </div>
  );
}
AnalyzersReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};

ConnectorsReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};

PivotsReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};

VisualizersReportTable.propTypes = {
  job: PropTypes.object.isRequired,
};
