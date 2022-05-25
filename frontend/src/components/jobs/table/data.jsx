/* eslint-disable react/prop-types */
import React from "react";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  SlicedText,
  DateHoverable
} from "@certego/certego-ui";

import { JobTag, StatusTag, TLPTag } from "../../common";
import { JOB_STATUSES, TLP_CHOICES, ALL_CLASSIFICATIONS } from "../../../constants";

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
      <DateHoverable ago
        value={value}
        Format="hh:mm:ss a MMM do, yyyy"
      />
    ),
    maxWidth: 125,
  },
  {
    Header: "Finished",
    id: "finished_analysis_time",
    accessor: "finished_analysis_time",
    Cell: ({ value, }) => (
      <DateHoverable ago
        value={value}
        format="hh:mm:ss a MMM do, yyyy"
      />
    ),
    maxWidth: 125,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user.username",
    Cell: ({ value, row: { original: job, }, }) => (
      <SlicedText
        id={`table-user-${job?.id}`}
        key={`table-user-${job?.id}`}
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Name",
    id: "name",
    accessor: (r) => r.observable_name || r.file_name,
    Cell: ({ value, row: { original: job, }, }) => (
      <SlicedText
        id={`table-name-${job?.id}`}
        key={`table-name-${job?.id}`}
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
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
  },
  {
    Header: "Settings",
    columns: [
      {
        Header: "Type",
        id: "type",
        accessor: (r) => r.observable_classification || r.file_mimetype,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: ALL_CLASSIFICATIONS,
      },
      {
        Header: "TLP",
        id: "tlp",
        accessor: "tlp",
        Cell: ({ value, }) => <TLPTag value={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: TLP_CHOICES,
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
              className="ms-2"
            />
          )),
        disableSortBy: true,
        Filter: DefaultColumnFilter,
        filterValueAccessorFn: (tags) => tags.map((t) => t.label),
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
              {job.analyzers_requested.length || "all"} analyzers
            </span>
            <span>
              {job.connectors_to_execute.length}/
              {job.connectors_requested.length || "all"} connectors
            </span>
          </div>
        ),
        disableSortBy: true,
        maxWidth: 175,
      },
      {
        Header: "Process Time (s)",
        id: "process_time",
        accessor: "process_time",
        disableSortBy: true,
        maxWidth: 125,
      },
      {
        Header: "Status",
        id: "status",
        accessor: "status",
        Cell: ({ value, }) => <StatusTag status={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: JOB_STATUSES,
      },
    ],
  },
];

export { jobTableColumns };
