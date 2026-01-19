/* eslint-disable react/prop-types */
import React from "react";
import { UncontrolledTooltip } from "reactstrap";
import { MdOutlineRefresh } from "react-icons/md";
import { IoSearch } from "react-icons/io5";

import {
  DateHoverable,
  DefaultColumnFilter,
  SelectOptionsFilter,
  IconButton,
} from "@certego/certego-ui";

import TableCell from "../common/TableCell";
import TagsCell from "../common/TagsCell";
import { ObservableClassifications } from "../../constants/jobConst";
import { LastEvaluationComponent } from "../common/engineBadges";

export const analyzablesTableColumns = [
  {
    Header: "ID",
    id: "id",
    accessor: "id",
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center p-2">
        {id ? (
          <div>
            <a
              id={`analyzableTable-${id}`}
              href={`/artifacts/${id}`}
              target="_blank"
              rel="noreferrer"
            >
              #{id}
            </a>
            <UncontrolledTooltip
              target={`analyzableTable-${id}`}
              placement="top"
              fade={false}
            >
              Artifact overview
            </UncontrolledTooltip>
          </div>
        ) : (
          <div className="fst-italic">NF</div>
        )}
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
        <div className="py-2">
          <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
        </div>
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
    Header: "Last evaluation",
    id: "evaluation",
    accessor: (analyzable) => analyzable?.last_data_model,
    Cell: ({ value, row }) =>
      value?.evaluation ? (
        <div className="d-flex justify-content-center py-2">
          <LastEvaluationComponent
            id={row.id}
            reliability={value.reliability}
            evaluation={value.evaluation}
          />
        </div>
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 120,
  },
  {
    Header: "Last evaluation date",
    id: "evaluation_date",
    accessor: (analyzable) => analyzable?.last_data_model,
    Cell: ({ value }) =>
      value?.date && value?.evaluation ? (
        <div className="py-2">
          <DateHoverable
            ago
            value={value.date}
            format="hh:mm:ss a MMM do, yyyy"
          />
        </div>
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 110,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: (analyzable) => analyzable?.last_data_model?.tags,
    Cell: ({ value: tags, row }) => <TagsCell values={tags} rowId={row.id} />,
    disableSortBy: true,
    maxWidth: 100,
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
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
