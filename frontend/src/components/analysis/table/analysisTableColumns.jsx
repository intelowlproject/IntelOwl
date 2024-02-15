/* eslint-disable react/prop-types */
import React from "react";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  DateHoverable,
  CopyToClipboardButton,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { TlpChoices } from "../../../constants/advancedSettingsConst";
import { AnalysisStatuses } from "../../../constants/analysisConst";

export const analysisTableColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 75,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center">
        <p>#{id}</p>
        <LinkOpenViewIcon
          id={id}
          href={`/analysis/${id}`}
          tooltip="View Analysis Report"
        />
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Created",
    id: "start_time",
    accessor: "start_time",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "owner",
    accessor: "owner",
    Cell: ({ value, row: { original: analysis } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-user-${analysis?.id}`}
        key={`table-user-${analysis?.id}`}
        text={value}
        className="d-block text-truncate"
      >
        {value}
      </CopyToClipboardButton>
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 120,
  },
  {
    Header: "Name",
    id: "name",
    accessor: "name",
    Cell: ({ value, row: { original: analysis } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-name-${analysis?.id}`}
        key={`table-name-${analysis?.id}`}
        text={value}
        className="d-block text-truncate"
      >
        {value}
      </CopyToClipboardButton>
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "TLP",
    id: "tlp",
    accessor: "tlp",
    Cell: ({ value }) => <TLPTag value={value} />,
    disableSortBy: true,
    Filter: SelectOptionsFilter,
    selectOptions: TlpChoices,
    maxWidth: 90,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: "tags",
    Cell: ({ value }) =>
      value.map(
        (tag) =>
          tag !== null && (
            <JobTag
              key={`jobtable-tags-${tag?.label}`}
              tag={tag}
              className="ms-2"
            />
          ),
      ),
    disableSortBy: true,
    maxWidth: 100,
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Jobs created",
    id: "total_jobs",
    accessor: "total_jobs",
    Cell: ({ value }) => value,
    disableSortBy: true,
    maxWidth: 90,
  },
  {
    Header: "Status",
    id: "status",
    accessor: "status",
    Cell: ({ value }) => <StatusTag status={value} />,
    disableSortBy: true,
    Filter: SelectOptionsFilter,
    selectOptions: Object.values(AnalysisStatuses),
    maxWidth: 110,
  },
];
