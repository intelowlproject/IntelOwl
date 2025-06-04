/* eslint-disable react/prop-types */
import React from "react";

import {
  DefaultColumnFilter,
  DateHoverable,
  CopyToClipboardButton,
} from "@certego/certego-ui";

export const userReportsTableColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 75,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div
        className="d-flex flex-column justify-content-center"
        id={`user-report-${id}`}
      >
        #{id}
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Created",
    id: "date",
    accessor: "date",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user.username",
    Cell: ({ value, row: { original: report } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-user-${report?.id}`}
        key={`table-user-${report?.id}`}
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
    Header: "Analyzable",
    id: "analyzable",
    accessor: "analyzable",
    Cell: ({ value, row: { original: report } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-analyzable-${report?.id}`}
        key={`table-analyzable-${report?.id}`}
        text={value}
        className="d-block text-truncate"
      >
        {value}
      </CopyToClipboardButton>
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 200,
  },
  {
    Header: "Decay",
    id: "next_decay",
    accessor: "next_decay",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
];
