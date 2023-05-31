/* eslint-disable camelcase */
/* eslint-disable react/prop-types */
import React from "react";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  SlicedText,
  DateHoverable,
} from "@certego/certego-ui";

import { JobTag, StatusTag, TLPTag } from "../../common";
import {
  JOB_STATUSES,
  TLP_CHOICES,
  ALL_CLASSIFICATIONS,
} from "../../../constants";

const process_time_mmss = (value) =>
  new Date(value * 1000).toISOString().substring(14, 19);

const jobTableColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 75,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div className="d-flex flex-column justify-content-center">
        <p>#{id}</p>
        <LinkOpenViewIcon
          id={id}
          href={`/jobs/${id}`}
          tooltip="View Job Report"
        />
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Created",
    id: "received_request_time",
    accessor: "received_request_time",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
  {
    Header: "Finished",
    id: "finished_analysis_time",
    accessor: "finished_analysis_time",
    Cell: ({ value }) =>
      value && (
        <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user.username",
    Cell: ({ value, row: { original: job } }) => (
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
    Cell: ({ value, row: { original: job } }) => (
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
    Cell: ({ value, row: { original: job } }) => (
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
        maxWidth: 100,
        Filter: SelectOptionsFilter,
        selectOptions: ALL_CLASSIFICATIONS,
      },
      {
        Header: "TLP",
        id: "tlp",
        accessor: "tlp",
        Cell: ({ value }) => <TLPTag value={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: TLP_CHOICES,
        maxWidth: 100,
      },
      {
        Header: "Tags",
        id: "tags",
        accessor: "tags",
        Cell: ({ value }) =>
          value.map((tag) => (
            <JobTag
              key={`jobtable-tags-${tag.label}`}
              tag={tag}
              className="ms-2"
            />
          )),
        disableSortBy: true,
        maxWidth: 100,
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
        Cell: ({ value: job }) => (
          <div className="d-flex flex-column justify-content-center">
            <span>
              {job.analyzers_to_execute.length}/{job.analyzers_requested.length}{" "}
              analyzers
            </span>
            <span>
              {job.connectors_to_execute.length}/
              {job.connectors_requested.length} connectors
            </span>
            <span>{job.visualizers_to_execute.length}/all visualizers</span>
          </div>
        ),
        disableSortBy: true,
        maxWidth: 175,
      },
      {
        Header: "Process Time (mm:ss)",
        id: "process_time",
        accessor: "process_time",
        Cell: ({ value }) => <span>{process_time_mmss(value)}</span>,
        maxWidth: 125,
      },
      {
        Header: "Status",
        id: "status",
        accessor: "status",
        Cell: ({ value }) => <StatusTag status={value} />,
        disableSortBy: true,
        Filter: SelectOptionsFilter,
        selectOptions: JOB_STATUSES,
      },
    ],
  },
];

export { jobTableColumns };
