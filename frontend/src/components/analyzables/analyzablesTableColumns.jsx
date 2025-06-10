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
import { ObservableClassifications } from "../../constants/jobConst";
import { TagsBadge, LastEvaluationComponent } from "../common/engineBadges";

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
              href={`/analyzables/${id}`}
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
              Analyzable overview
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
    accessor: (analyzable) =>
      analyzable?.jobs
        .concat(analyzable?.user_events)
        .sort((elA, elB) => new Date(elB.date) - new Date(elA.date))[0],
    Cell: ({ value, row }) =>
      value?.data_model?.evaluation ? (
        <div className="d-flex justify-content-center py-2">
          <LastEvaluationComponent
            id={row.id}
            reliability={value.data_model.reliability}
            evaluation={value.data_model.evaluation}
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
    accessor: (analyzable) =>
      analyzable?.jobs
        .concat(analyzable?.user_events)
        .sort((elA, elB) => new Date(elB.date) - new Date(elA.date))[0],
    Cell: ({ value }) =>
      value?.data_model?.date && value.data_model.evaluation ? (
        <div className="py-2">
          <DateHoverable
            ago
            value={value.data_model.date}
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
    accessor: (analyzable) => {
      if (analyzable.id === undefined)
        return { data_model: { tags: ["not_found"] } };
      return analyzable?.jobs
        .concat(analyzable?.user_events)
        .sort((elA, elB) => new Date(elB.date) - new Date(elA.date))[0];
    },
    Cell: ({ value, row }) =>
      value?.data_model?.tags ? (
        <div className="d-flex justify-content-center py-2">
          {value.data_model.tags.map((tag, index) => (
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
