/* eslint-disable react/prop-types */
import React from "react";
import { UncontrolledTooltip } from "reactstrap";

import {
  DateHoverable,
  DefaultColumnFilter,
  SelectOptionsFilter,
  CopyToClipboardButton,
} from "@certego/certego-ui";

import TableCell from "../common/TableCell";
import { ObservableClassifications } from "../../constants/jobConst";
import { PlaybookInfoPopoverIcon } from "../jobs/table/playbookJobInfo";

export const analyzablesTableColumns = [
  {
    Header: "ID",
    id: "id",
    accessor: "id",
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center">
        <a
          id={`analyzable-${id}`}
          href={`/analyzables/${id}`}
          target="_blank"
          rel="noreferrer"
        >
          #{id}
        </a>
        <UncontrolledTooltip
          target={`analyzable-${id}`}
          placement="top"
          fade={false}
        >
          Analyzable overview
        </UncontrolledTooltip>
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
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
  },
  {
    Header: "SHA 256",
    id: "sha256",
    accessor: "sha256",
    Cell: ({ value, row: { original: analyzable } }) => (
      <TableCell
        id={`table-cell-sha256__${analyzable.id}`}
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
    id: "date",
    accessor: "date",
    Cell: ({ value }) => (
      // <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      <div>test {value}</div>
    ),
    disableSortBy: true,
  },
  {
    Header: "Last Evaluation",
    id: "evaluation",
    accessor: "evaluation",
    Cell: ({ value }) => <div>test {value}</div>,
    disableSortBy: true,
    maxWidth: 120,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: "tags",
    Cell: ({ value }) => <div>test {value}</div>,
    // value.map((tag) => (
    //   <JobTag key={`jobtable-tags-${tag.label}`} tag={tag} className="ms-2" />
    // )),
    disableSortBy: true,
    maxWidth: 100,
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Playbook",
    id: "playbook_to_execute",
    accessor: (job) => job,
    Cell: ({ value: job }) => {
      const playbookName = job.playbook_to_execute || "Custom analysis";
      return (
        <div className="d-flex justify-content-between">
          <span className="d-block text-truncate">
            <CopyToClipboardButton showOnHover text={playbookName}>
              {playbookName}
            </CopyToClipboardButton>
          </span>
          <PlaybookInfoPopoverIcon job={job} />
        </div>
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
    Cell: ({ value }) => (
      <div className="d-flex justify-content-center mx-2">{value.name}</div>
    ),
    maxWidth: 80,
  },
];
