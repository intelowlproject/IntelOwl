/* eslint-disable react/prop-types */
import React from "react";
import PropTypes from "prop-types";
import Moment from "react-moment";
import { MdOutlineRefresh, MdPauseCircleOutline } from "react-icons/md";

import {
  CustomJsonInput,
  DataTable,
  DefaultColumnFilter,
  IconButton,
  SelectOptionsFilter
} from "@certego/certego-ui";

import { StatusTag } from "../../../common";
import { PLUGIN_STATUSES } from "../../../../constants";
import { killPlugin, retryPlugin } from "../api";

const tableProps = {
  columns: [
    {
      Header: () => null,
      id: "actions",
      accessor: (r) => r,
      maxWidth: 60,
      disableSortBy: true,
      Cell: ({ value: plugin, customProps: { job, refetch, }, }) => (
        <div className="d-flex-center">
          {job.permissions?.plugin_actions === true &&
            ["running", "pending"].includes(plugin.status.toLowerCase()) && (
              <IconButton
                id={`killplugin-${plugin.name}`}
                Icon={MdPauseCircleOutline}
                onClick={() =>
                  killPlugin(job.id, plugin.type, plugin.name).then(refetch)
                }
                color="accent"
                size="xs"
                title={`Kill ${plugin.type} run`}
                titlePlacement="top"
                className="mr-2 border-0"
              />
            )}
          {job.permissions?.plugin_actions === true &&
            ["failed", "killed"].includes(plugin.status.toLowerCase()) && (
              <IconButton
                id={`retryplugin-${plugin.name}`}
                Icon={MdOutlineRefresh}
                onClick={() =>
                  retryPlugin(job.id, plugin.type, plugin.name).then(refetch)
                }
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
      Cell: ({ value, }) => <StatusTag status={value} />,
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
      Cell: ({ value: plugin, }) => (
        <div>
          <Moment date={plugin?.start_time} format="hh:mm:ss a" />
          &nbsp;<span className="font-weight-bold text-muted">-</span>&nbsp;
          <Moment date={plugin?.end_time} format="hh:mm:ss a" />
          &nbsp;
          <Moment date={plugin?.end_time} format="(Z)" />
        </div>
      ),
    },
  ],
  config: { enableExpanded: true, enableFlexLayout: true, },
  initialState: {
    pageSize: 10,
    sortBy: [
      { id: "status", desc: true, },
      { id: "name", desc: true, },
    ],
  },
  SubComponent: ({ row, }) => (
    <CustomJsonInput
      viewOnly
      confirmGood={false}
      onChange={() => null}
      key={row.id}
      id={`jobreport-jsoninput-${row.id}`}
      placeholder={{
        report: row.original?.report,
        errors: row.original?.errors,
        runtime_configuration: row.original?.runtime_configuration,
      }}
      height="50vh"
      width="90vw"
    />
  ),
};

export function AnalyzersReportTable({ job, refetch, }) {
  return (
    <DataTable
      data={job?.analyzer_reports}
      customProps={{ job, refetch, }}
      {...tableProps}
    />
  );
}

export function ConnectorsReportTable({ job, refetch, }) {
  return (
    <DataTable
      data={job?.connector_reports}
      customProps={{ job, refetch, }}
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
