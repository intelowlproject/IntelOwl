/* eslint-disable react/prop-types */
import React from "react";
import { UncontrolledTooltip } from "reactstrap";

import {
  DateHoverable,
  DefaultColumnFilter,
  SelectOptionsFilter,
} from "@certego/certego-ui";

import TableCell from "../../common/TableCell";
import { TagsBadge, LastEvaluationComponent } from "../../common/engineBadges";
import { JobResultSections } from "../../../constants/miscConst";

export const analyzablesHistoryTableColumns = [
  {
    Header: "ID",
    id: "pk",
    accessor: "id",
    Cell: ({ value: id, row: { original } }) => (
      <div className="d-flex flex-column justify-content-center p-2">
        {original.type === "job" ? (
          <div>
            <a
              id={`analyzable-history__job-${id}`}
              href={`/jobs/${id}/${JobResultSections.VISUALIZER}`}
              target="_blank"
              rel="noreferrer"
            >
              #{id}
            </a>
            <UncontrolledTooltip
              target={`analyzable-history__job-${id}`}
              placement="top"
              fade={false}
            >
              Job overview
            </UncontrolledTooltip>
          </div>
        ) : (
          <div>
            <a
              id={`analyzable-history__report-${id}`}
              // to be modified with the correct url when the dedicated page will be created
              href={`/analyzables/${id}`}
              target="_blank"
              rel="noreferrer"
            >
              #{id}
            </a>
            <UncontrolledTooltip
              target={`analyzable-history__report-${id}`}
              placement="top"
              fade={false}
            >
              Report overview
            </UncontrolledTooltip>
          </div>
        )}
      </div>
    ),
    disableSortBy: true,
    maxWidth: 60,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user.username",
    Cell: ({ value, row: { original } }) => (
      <TableCell
        id={`table-cell-user__${original.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 90,
  },
  {
    Header: "Date",
    id: "date",
    accessor: "date",
    Cell: ({ value }) =>
      value ? (
        <div className="py-2">
          <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
        </div>
      ) : (
        <div />
      ),
    maxWidth: 110,
  },
  {
    Header: "Type",
    id: "type",
    accessor: "type",
    disableSortBy: true,
    maxWidth: 90,
    Filter: SelectOptionsFilter,
    selectOptions: ["job", "user report"],
    Cell: ({ value, row: { original } }) => (
      <TableCell id={`table-cell-type__${original.id}`} value={value} />
    ),
  },
  {
    Header: "Evaluation",
    id: "evaluation",
    accessor: (analyzable) => analyzable.data_model,
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
    maxWidth: 120,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: "data_model.tags",
    Cell: ({ value, row }) =>
      value ? (
        <div className="d-flex justify-content-center py-2">
          {value.map((tag, index) => (
            <TagsBadge
              id={`row${row.id}_${index}`}
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
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Description",
    id: "actions",
    accessor: (value) =>
      value.type === "job"
        ? `Playbook executed: ${value.playbook}`
        : value.data_model.related_threats.toString(),
    disableSortBy: true,
    Cell: ({ value, row }) =>
      value && (
        <TableCell
          id={`table-cell-description__${row.id}`}
          isCopyToClipboard
          isTruncate
          value={value}
        />
      ),
    minWidth: 200,
  },
];
