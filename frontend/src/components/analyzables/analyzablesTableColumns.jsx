/* eslint-disable react/prop-types */
import React from "react";
// import { UncontrolledTooltip } from "reactstrap";
import { MdOutlineRefresh } from "react-icons/md";
import { IoSearch } from "react-icons/io5";

import {
  DateHoverable,
  DefaultColumnFilter,
  SelectOptionsFilter,
  IconButton,
} from "@certego/certego-ui";

import TableCell from "../common/TableCell";
import { ObservableClassifications } from "../../constants/jobConst";
import { TagsBadge, LastEvaluationComponent } from "../common/engineBadges";

export const analyzablesTableColumns = [
  {
    Header: "ID",
    id: "id",
    accessor: "id",
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center p-2">
        {id ? <div id={`analyzable-${id}`}>#{id}</div> : <div>NF</div>}
      </div>
    ),
    disableSortBy: true,
    maxWidth: 60,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Name",
    id: "name",
    accessor: "name",
    Cell: ({ value, row: { original: analyzable } }) => (
      <TableCell
        id={`table-cell-name__${analyzable.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Discovery date",
    id: "discovery_date",
    accessor: "discovery_date",
    Cell: ({ value }) =>
      value ? (
        <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      ) : (
        <div />
      ),
    maxWidth: 110,
  },
  {
    Header: "SHA 256",
    id: "sha256",
    accessor: "sha256",
    Cell: ({ value, row: { original: analyzable } }) =>
      value ? (
        <TableCell
          id={`table-cell-sha256__${analyzable.id}`}
          isCopyToClipboard
          isTruncate
          value={value}
        />
      ) : (
        <div />
      ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 100,
  },
  {
    Header: "Classification",
    id: "classification",
    accessor: "classification",
    disableSortBy: true,
    maxWidth: 90,
    Filter: SelectOptionsFilter,
    selectOptions: Object.values(ObservableClassifications)
      .sort()
      .concat("file"),
    Cell: ({ value, row: { original: analyzable } }) => (
      <TableCell
        id={`table-cell-classification__${analyzable.id}`}
        value={value}
      />
    ),
  },
  {
    Header: "Last Analysis",
    id: "last_analysis",
    accessor: "last_analysis",
    Cell: ({ value }) =>
      value ? (
        <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 110,
  },
  {
    Header: "Last Evaluation",
    id: "evaluation",
    accessor: (analyzable) => analyzable,
    Cell: ({ value: analyzable, row }) =>
      analyzable.last_evaluation ? (
        <div className="d-flex justify-content-center py-2">
          <LastEvaluationComponent
            id={row.id}
            reliability={analyzable.last_reliability}
            evaluation={analyzable.last_evaluation}
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
    accessor: "tags",
    Cell: ({ value, row }) =>
      value ? (
        <div className="d-flex justify-content-center py-2">
          {value.map((tag, index) => (
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
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Playbook",
    id: "playbook_to_execute",
    accessor: (analyzable) => analyzable,
    Cell: ({ value: analyzable, row }) => {
      const playbookName = analyzable.playbook_to_execute || "Custom analysis";
      return analyzable.id ? (
        <TableCell
          id={`table-cell-playbook__${row.id}`}
          isCopyToClipboard
          isTruncate
          value={playbookName}
        />
      ) : (
        <div />
      );
    },
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 100,
  },
  {
    Header: "Actions",
    id: "actions",
    accessor: (analyzable) => analyzable,
    disableSortBy: true,
    Cell: ({ value: analyzable, row }) => (
      <div className="d-flex justify-content-center mx-2 py-1">
        <IconButton
          id={`scanbtn_${row.id}`}
          Icon={analyzable.id ? MdOutlineRefresh : IoSearch}
          size="sm"
          color="info"
          title={analyzable.id ? "Rescan analyzable" : "Scan analyzable"}
          titlePlacement="top"
          href={`/scan?observable=${analyzable.name}`}
          target="_blank"
          rel="noreferrer"
        />
      </div>
    ),
    maxWidth: 80,
  },
];
