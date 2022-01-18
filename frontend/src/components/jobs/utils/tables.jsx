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

import { StatusTag } from "../../common";
import { PLUGIN_STATUSES } from "../../../constants";
import { killPlugin, retryPlugin } from "./api";

const tableProps = {
  columns: [
    {
      Header: () => null,
      id: "actions",
      accessor: (r) => r,
      maxWidth: 60,
      disableSortBy: true,
      Cell: ({ value: plugin, customProps: { jobId, refetch, }, }) => (
        <div className="d-flex-center">
          {["running", "pending"].includes(plugin.status.toLowerCase()) && (
            <IconButton
              id={`killplugin-${plugin.name}`}
              Icon={MdPauseCircleOutline}
              onClick={() =>
                killPlugin(jobId, plugin.type, plugin.name).then(refetch)
              }
              color="accent"
              size="xs"
              title={`Kill ${plugin.type} run`}
              titlePlacement="top"
              className="mr-2 border-0"
            />
          )}
          {["failed", "killed"].includes(plugin.status.toLowerCase()) && (
            <IconButton
              id={`retryplugin-${plugin.name}`}
              Icon={MdOutlineRefresh}
              onClick={() =>
                retryPlugin(jobId, plugin.type, plugin.name).then(refetch)
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
      maxWidth: 75,
    },
    {
      Header: "Name",
      id: "name",
      accessor: "name",
      Filter: DefaultColumnFilter,
      minWidth: 200,
    },

    {
      Header: "Process Time (s)",
      id: "process_time",
      accessor: "process_time",
      maxWidth: 100,
    },
    {
      Header: "Start Time",
      id: "start_time",
      accessor: "start_time",
      Cell: ({ value, }) => (
        <Moment date={value} format="h:mm A MMM Do, YYYY Z" />
      ),
      maxWidth: 150,
    },
    {
      Header: "End Time",
      id: "end_time",
      accessor: "end_time",
      Cell: ({ value, }) => (
        <Moment date={value} format="h:mm A MMM Do, YYYY Z" />
      ),
      maxWidth: 150,
    },
  ],
  config: { enableExpanded: true, },
  initialState: {
    pageSize: 10,
    sortBy: [
      { id: "status", desc: false, },
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
      customProps={{ jobId: job.id, refetch, }}
      {...tableProps}
    />
  );
}

export function ConnectorsReportTable({ job, refetch, }) {
  return (
    <DataTable
      data={job?.connector_reports}
      customProps={{ jobId: job.id, refetch, }}
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
