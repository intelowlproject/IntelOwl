/* eslint-disable react/prop-types */
import React from "react";
import Moment from "react-moment";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  SlicedText,
  SelectColumnFilter
} from "@certego/certego-ui";

import { JobTag, StatusTag, TLPTag } from "../common";
import { JOB_STATUSES, TLP_CHOICES } from "../../constants";

const jobTableColumns = [
  {
    Header: () => null, // No header
    id: "viewJobBtnHeader",
    accessor: "id",
    maxWidth: 50,
    disableSortBy: true,
    Cell: ({ value: id, }) => (
      <LinkOpenViewIcon
        id={id}
        href={`/jobs/${id}`}
        tooltip="View Job Report"
      />
    ),
  },
  {
    Header: "Created",
    id: "received_request_time",
    accessor: "received_request_time",
    Cell: ({ value, }) => (
      <Moment fromNow withTitle date={value} titleFormat="Do MMMM YYYY" />
    ),
    maxWidth: 125,
  },
  {
    Header: "Finished",
    id: "finished_analysis_time",
    accessor: "finished_analysis_time",
    Cell: ({ value, }) => (
      <Moment fromNow withTitle date={value} titleFormat="Do MMMM YYYY" />
    ),
    maxWidth: 125,
  },
  {
    Header: "Name",
    id: "name",
    accessor: (r) => r.observable_name || r.file_name,
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    minWidth: 175,
  },
  {
    Header: "MD5",
    id: "md5",
    accessor: "md5",
    Cell: ({ value, row: { original: job, }, }) => (
      <SlicedText
        id={`table-md5-${job?.id}`}
        key={`table-md5-${job?.id}`}
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    minWidth: 200,
  },
  {
    Header: "Settings",
    columns: [
      {
        Header: "Type",
        id: "type",
        accessor: (r) => r.observable_classification || r.file_mimetype,
        disableSortBy: true,
        Filter: SelectColumnFilter,
        minWidth: 175,
      },
      {
        Header: "TLP",
        id: "tlp",
        accessor: "tlp",
        Cell: ({ value, }) => <TLPTag value={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: TLP_CHOICES,
        minWidth: 175,
      },
      {
        Header: "Tags",
        id: "tags",
        accessor: "tags",
        Cell: ({ value, }) =>
          value.map((tag) => (
            <JobTag
              key={`jobtable-tags-${tag.label}`}
              tag={tag}
              className="ml-2"
            />
          )),
        disableSortBy: true,
        Filter: SelectColumnFilter,
        filterValueAccessorFn: (tags) => tags.map((t) => t.label),
        minWidth: 200,
      },
    ],
  },
  {
    Header: "Computed",
    columns: [
      {
        Header: "Plugins Executed",
        id: "plugins",
        accessor: (r) => r,
        Cell: ({ value: job, }) => (
          <div className="d-flex flex-column align-items-start">
            <span>
              {job.analyzers_to_execute.length}/
              {job.analyzers_requested.length || "-"} analyzers
            </span>
            <span>
              {job.connectors_to_execute.length}/
              {job.connectors_requested.length || "-"} connectors
            </span>
          </div>
        ),
        disableSortBy: true,
        maxWidth: 150,
      },
      {
        Header: "Process Time (s)",
        id: "process_time",
        accessor: "process_time",
        disableSortBy: true,
        maxWidth: 150,
      },
      {
        Header: "Status",
        id: "status",
        accessor: "status",
        Cell: ({ value, }) => <StatusTag status={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: JOB_STATUSES,
        minWidth: 220,
      },
    ],
  },
];

export { jobTableColumns };
