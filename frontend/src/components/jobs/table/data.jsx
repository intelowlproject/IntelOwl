/* eslint-disable camelcase */
/* eslint-disable react/prop-types */
import React from "react";
import { Input } from "reactstrap";
import classnames from "classnames";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  SlicedText,
  DateHoverable,
} from "@certego/certego-ui";

import { JobTag, StatusTag, TLPTag } from "../../common";
import {
  TLP_CHOICES,
  FILE_MIME_TYPES,
  OBSERVABLE_CLASSIFICATION,
} from "../../../constants";
import { jobStatuses, jobResultSection } from "../../../constants/constants";

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
          href={`/jobs/${id}/${jobResultSection.VISUALIZER}`}
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
        id: "is_sample",
        accessor: (r) => r.is_sample,
        Cell: ({ value }) => (value ? "file" : "observable"),
        disableSortBy: true,
        maxWidth: 100,
        Filter: ({
          column: { filterValue: isSampleStr, setFilter, id, selectOptions },
        }) => {
          const onChange = (dropdownSelector) => {
            /* in case the user selected a value from the dropodown ("file", "observable")
                we need to convert it to a boolean value, because we will send the request to the backend
                for the field is_sample that requires a bool.
              */
            if (dropdownSelector.target.value) {
              /* even if the backend requires a bool, we need to cast it to string or 
                the library won't send the request for the false case (observable filter)
              */
              setFilter((dropdownSelector.target.value === "file").toString());
            } else {
              /* in case of no selection set to undefined, in this way the library will remove the param from the request
                this is the "all" case (both samples and observables)
              */
              setFilter(undefined);
            }
          };

          // this is the label to show in the dropdown as selected element
          let SelectedDropdownElementlabel = "All";
          if (isSampleStr !== undefined) {
            SelectedDropdownElementlabel =
              isSampleStr === "true" ? "file" : "observable";
          }

          return (
            <Input
              id={`datatable-select-${id}`}
              type="select"
              className={classnames(
                {
                  "bg-body border-secondary": isSampleStr,
                },
                "custom-select-sm input-dark",
              )}
              value={SelectedDropdownElementlabel}
              onChange={onChange}
            >
              <option value="">All</option>
              {selectOptions.map((value) => (
                <option
                  key={`datatable-select-${id}-option-${value}`}
                  value={value}
                >
                  {value}
                </option>
              ))}
            </Input>
          );
        },
        selectOptions: ["file", "observable"],
      },
      {
        Header: "SubType",
        id: "type",
        accessor: (r) => r.observable_classification || r.file_mimetype,
        disableSortBy: true,
        maxWidth: 100,
        Filter: SelectOptionsFilter,
        selectOptions: Object.values(OBSERVABLE_CLASSIFICATION)
          .sort()
          .concat(Object.values(FILE_MIME_TYPES).sort()),
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
            <span>{job.pivots_to_execute.length}/ all pivots</span>
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
        selectOptions: Object.values(jobStatuses),
      },
    ],
  },
];

export { jobTableColumns };
