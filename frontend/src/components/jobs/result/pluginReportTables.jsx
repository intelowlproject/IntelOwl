/* eslint-disable react/prop-types */
import React from "react";
import PropTypes from "prop-types";
import {
  MdOutlineRefresh,
  MdPauseCircleOutline,
  MdInfoOutline,
} from "react-icons/md";
import { JSONTree } from "react-json-tree";
import { UncontrolledPopover } from "reactstrap";

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
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { markdownToHtml } from "../../common/markdownToHtml";

const tableProps = {
  columns: [
    {
      Header: "Actions",
      id: "actions",
      accessor: (pluginReport) => pluginReport,
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
      Cell: ({ value }) => <StatusTag status={value} className="py-0" />,
      Filter: SelectOptionsFilter,
      selectOptions: Object.values(PluginStatuses),
      maxWidth: 50,
    },
    {
      Header: "Name",
      id: "name",
      accessor: "name",
      Cell: ({
        value,
        row: { original: plugin },
        customProps: { _job, _refetch, pluginsLoading },
      }) => (
        <div className="d-flex align-items-center row">
          <div className="d-inline-block col-10 offset-1">{value}</div>
          <div className="col-1">
            <MdInfoOutline
              id={`pluginReport-infoicon__${value}`}
              className="text-secondary"
              fontSize="20"
            />
            <UncontrolledPopover
              target={`pluginReport-infoicon__${value}`}
              placement="bottom"
              trigger="hover"
              popperClassName="px-2 bg-body"
              delay={{ show: 0, hide: 200 }}
              style={{ paddingTop: "1rem" }}
            >
              {pluginsLoading ? (
                <small>
                  <p>Description is loading</p>
                </small>
              ) : (
                <small>{markdownToHtml(plugin?.description)}</small>
              )}
            </UncontrolledPopover>
          </div>
        </div>
      ),
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
      accessor: (pluginReport) => pluginReport,
      disableSortBy: true,
      maxWidth: 125,
      Cell: ({ value: plugin }) => (
        <div>
          <DateHoverable value={plugin?.start_time} format="pp" />
          &nbsp;<span className="fw-bold text-muted">-</span>&nbsp;
          <DateHoverable value={plugin?.end_time} format="pp" />
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
  const reports = job?.analyzer_reports;

  const [analyzers, analyzersLoading] = usePluginConfigurationStore((state) => [
    state.analyzers,
    state.analyzersLoading,
  ]);

  reports.forEach((report, index) => {
    analyzers.forEach((analyzer) => {
      if (analyzer.name === report.name) {
        reports[index].description = analyzer.description;
      }
    });
  });

  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={reports}
        customProps={{ job, refetch, pluginsLoading: analyzersLoading }}
        {...tableProps}
      />
    </div>
  );
}

export function ConnectorsReportTable({ job, refetch }) {
  console.debug("ConnectorsReportTable rendered");
  const reports = job?.connector_reports;

  const [connectors, connectorsLoading] = usePluginConfigurationStore(
    (state) => [state.connectors, state.connectorsLoading],
  );

  reports.forEach((report, index) => {
    connectors.forEach((connector) => {
      if (connector.name === report.name) {
        reports[index].description = connector.description;
      }
    });
  });

  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={reports}
        customProps={{ job, refetch, pluginsLoading: connectorsLoading }}
        {...tableProps}
      />
    </div>
  );
}
export function PivotsReportTable({ job, refetch }) {
  console.debug("PivotsReportTable rendered");
  const reports = job?.pivot_reports;

  const [pivots, pivotsLoading] = usePluginConfigurationStore((state) => [
    state.pivots,
    state.pivotsLoading,
  ]);

  reports.forEach((report, index) => {
    pivots.forEach((pivot) => {
      if (pivot.name === report.name) {
        reports[index].description = pivot.description;
      }
    });
  });

  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={reports}
        customProps={{ job, refetch, pluginsLoading: pivotsLoading }}
        {...tableProps}
      />
    </div>
  );
}
export function VisualizersReportTable({ job, refetch }) {
  console.debug("VisualizersReportTable rendered");
  const reports = job?.visualizer_reports;

  const [visualizers, visualizersLoading] = usePluginConfigurationStore(
    (state) => [state.visualizers, state.visualizersLoading],
  );

  reports.forEach((report, index) => {
    visualizers.forEach((visualizer) => {
      if (visualizer.name === report.name) {
        reports[index].description = visualizer.description;
      }
    });
  });

  return (
    <div style={{ height: "60vh", overflow: "scroll" }}>
      <DataTable
        data={reports}
        customProps={{ job, refetch, pluginsLoading: visualizersLoading }}
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
