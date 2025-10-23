/* eslint-disable react/prop-types */
import React from "react";

import { DefaultColumnFilter, DateHoverable } from "@certego/certego-ui";

import { LastEvaluationComponent, TagsBadge } from "../common/engineBadges";
import { UserEventDecay } from "./UserEventDecay";
import TableCell from "../common/TableCell";

export const userEventsTableStartColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 65,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div
        className="d-flex flex-column justify-content-center py-2"
        id={`user-report-${id}`}
      >
        #{id}
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Date",
    id: "date",
    accessor: "data_model.date",
    Cell: ({ value }) => (
      <div className="py-2">
        <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      </div>
    ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "username",
    accessor: "user",
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-user__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 100,
  },
];

export const userEventsTableEndColumns = [
  {
    Header: "Evaluation",
    id: "evaluation",
    accessor: (userEvent) => userEvent.data_model,
    Cell: ({ value: dataModel, row }) =>
      dataModel.evaluation ? (
        <div className="d-flex justify-content-center py-2">
          <LastEvaluationComponent
            id={row.id}
            reliability={dataModel.reliability}
            evaluation={dataModel.evaluation}
          />
        </div>
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    Header: "Decay",
    id: "next_decay",
    accessor: (userEvent) => userEvent,
    Cell: ({ value: userEvent }) => (
      <UserEventDecay
        decay={userEvent.next_decay}
        reliability={userEvent.data_model.reliability}
      />
    ),
    maxWidth: 100,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: (userEvent) => userEvent.data_model.tags,
    Cell: ({ value: tags, row }) =>
      tags ? (
        <div className="d-flex justify-content-center py-2">
          {tags.map((tag, index) => (
            <TagsBadge
              id={`tag-row${row.id}_${index}`}
              tag={tag}
              className="ms-1"
            />
          ))}
        </div>
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    Header: "Reasons",
    id: "related_threats",
    accessor: (userEvent) => userEvent.data_model.related_threats,
    Cell: ({ value: comments, row }) =>
      comments.length > 0 && (
        <TableCell
          id={`table-cell-related_threats__${row?.id}`}
          isCopyToClipboard
          isTruncate
          value={comments?.toString()}
        />
      ),
    disableSortBy: true,
    maxWidth: 160,
  },
];

export const userAnalyzableEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Artifact",
    id: "analyzable_name",
    accessor: (userEvent) => userEvent?.analyzable?.name,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-analyzable__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 160,
  },
  ...userEventsTableEndColumns,
];

export const userDomainWildcardEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Query",
    id: "analyzables_name",
    accessor: (userEvent) => userEvent?.query,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-query__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 160,
  },
  ...userEventsTableEndColumns,
];

export const userIpWildcardEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Network",
    id: "ip",
    accessor: (userEvent) => userEvent,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-network__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={`${value.start_ip} - ${value.end_ip}`}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 140,
  },
  ...userEventsTableEndColumns,
];
