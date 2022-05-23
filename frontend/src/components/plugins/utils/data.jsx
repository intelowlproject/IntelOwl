/* eslint-disable react/prop-types */
/* eslint-disable react/no-array-index-key */
import React from "react";
import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  BooleanIcon,
  SelectColumnFilter
} from "@certego/certego-ui";

import { TLP_CHOICES } from "../../../constants";
import { markdownToHtml, TLPTag } from "../../common";
import {
  PluginHealthCheckButton,
  PluginInfoPopoverIcon,
  PluginVerificationIcon
} from "./utils";

const pluginTableColumns = [
  {
    Header: "Info",
    id: "info",
    accessor: (r) => r,
    Cell: ({ value, }) => <PluginInfoPopoverIcon pluginInfo={value} />,
    disableSortBy: true,
    maxWidth: 80,
  },
  {
    Header: "Name",
    id: "name",
    accessor: "name",
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Active",
    id: "active",
    accessor: (r) => !r.disabled,
    Cell: ({ value, }) => <BooleanIcon withColors truthy={value} />,
    Filter: SelectOptionsFilter,
    selectOptions: ["true", "false"],
    disableSortBy: true,
    maxWidth: 115,
  },
  {
    Header: "Configured",
    id: "configured",
    accessor: "verification.configured",
    Cell: ({ row: { original, }, }) => (
      <PluginVerificationIcon
        pluginName={original?.name}
        verification={original?.verification}
      />
    ),
    Filter: SelectOptionsFilter,
    selectOptions: ["true", "false"],
    disableSortBy: true,
    maxWidth: 115,
  },
];

const analyzersTableColumns = [
  ...pluginTableColumns,
  {
    Header: "Description",
    id: "description",
    accessor: "description",
    Cell: ({ value, }) => <span>{markdownToHtml(value)}</span>,
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Type",
    id: "type",
    accessor: "type",
    disableSortBy: true,
    Filter: SelectOptionsFilter,
    selectOptions: ["observable", "file"],
  },
  {
    Header: "Supported types",
    id: "supported_types",
    accessor: (r) => {
        let supported;
        if (r.type === "observable"){
            supported = r.observable_supported;
        } else {
            supported = r.supported_filetypes;
        }
        if (supported.length === 0){supported.push("everything");}
        return supported;
    },
    Cell: ({ value, }) => (
      <ul className="d-flex flex-column align-items-start">
        {value?.map((v) => (
          <li key={v}>{v}</li>
        ))}
      </ul>
    ),
    disableSortBy: true,
    Filter: SelectColumnFilter,
  },
  {
    Header: "External Service",
    id: "external_service",
    accessor: "external_service",
    Cell: ({ value, }) => <BooleanIcon withColors truthy={value} />,
    Filter: SelectOptionsFilter,
    selectOptions: ["true", "false"],
    disableSortBy: true,
    maxWidth: 115,
  },
  {
    Header: "Leaks Info",
    id: "leaks_info",
    accessor: "leaks_info",
    Cell: ({ value, }) => <BooleanIcon withColors truthy={value} />,
    Filter: SelectOptionsFilter,
    selectOptions: ["true", "false"],
    disableSortBy: true,
    maxWidth: 115,
  },
  {
    Header: "Health Check",
    id: "health_check",
    accessor: (r) => r,
    disableSortBy: true,
    Cell: ({ value, }) =>
      value?.docker_based && (
        <PluginHealthCheckButton
          pluginName={value.name}
          pluginType="analyzer"
        />
      ),
    maxWidth: 115,
  },
];

const connectorTableColumns = [
  ...pluginTableColumns,
  {
    Header: "Description",
    id: "description",
    accessor: "description",
    Cell: ({ value, }) => <span>{markdownToHtml(value)}</span>,
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Maximum TLP",
    id: "maximum_tlp",
    accessor: "maximum_tlp",
    Cell: ({ value, }) => <TLPTag value={value} />,
    Filter: SelectOptionsFilter,
    selectOptions: TLP_CHOICES,
  },
  {
    Header: "Health Check",
    id: "health_check",
    accessor: (r) => r,
    disableSortBy: true,
    Cell: ({ value, }) => (
      <PluginHealthCheckButton
        pluginName={value?.name}
        pluginType="connector"
      />
    ),
    maxWidth: 125,
  },
];

export { analyzersTableColumns, connectorTableColumns };
