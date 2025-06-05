/* eslint-disable react/prop-types */
import React from "react";

import { DefaultColumnFilter, DateHoverable } from "@certego/certego-ui";

import { LastEvaluationComponent, TagsBadge } from "../../common/engineBadges";
import TableCell from "../../common/TableCell";

export const userReportsTableColumns = [
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
    accessor: "date",
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
  {
    Header: "Analyzable",
    id: "analyzable_name",
    accessor: "analyzable",
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
    accessor: "next_decay",
    Cell: ({ value }) =>
      value ? (
        <div className="py-2">
          <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
        </div>
      ) : (
        <span className="text-secondary fst-italic">Decayed</span>
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
    Header: "Comments",
    id: "related_threats",
    accessor: (userEvent) => userEvent.data_model.related_threats,
    Cell: ({ value: comments, row }) =>
      comments.length > 0 && (
        <TableCell
          id={`table-cell-analyzable__${row?.id}`}
          isCopyToClipboard
          isTruncate
          value={comments?.toString()}
        />
      ),
    disableSortBy: true,
    maxWidth: 160,
  },
];
