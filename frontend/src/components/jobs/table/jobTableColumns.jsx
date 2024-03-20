/* eslint-disable react/prop-types */
import React from "react";
import { Input } from "reactstrap";
import classnames from "classnames";

import {
  DefaultColumnFilter,
  SelectOptionsFilter,
  LinkOpenViewIcon,
  DateHoverable,
  CopyToClipboardButton,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { TlpChoices } from "../../../constants/advancedSettingsConst";
import {
  JobStatuses,
  FileMimeTypes,
  ObservableClassifications,
  JobTypes,
} from "../../../constants/jobConst";
import { JobResultSections } from "../../../constants/miscConst";
import { PlaybookInfoPopoverIcon } from "./playbookJobInfo";
import { processTimeMMSS } from "../../../utils/time";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import TableCell from "../../common/TableCell";

export const jobTableColumns = [
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
          href={`/jobs/${id}/${JobResultSections.VISUALIZER}`}
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
      <TableCell job={job} isCopyToClipboard isTruncate value={value} />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 120,
  },
  {
    Header: "Name",
    id: "name",
    accessor: (job) => job.observable_name || job.file_name,
    Cell: ({ value, row: { original: job } }) => (
      <TableCell job={job} value={value} isCopyToClipboard isTruncate />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "MD5",
    id: "md5",
    accessor: "md5",
    Cell: ({ value, row: { original: job } }) => (
      <TableCell job={job} isCopyToClipboard isTruncate value={value} />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Type",
    id: "is_sample",
    accessor: (job) => job.is_sample,
    Cell: ({ value }) => (value ? JobTypes.FILE : JobTypes.OBSERVABLE),
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
          setFilter(
            (dropdownSelector.target.value === JobTypes.FILE).toString(),
          );
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
          isSampleStr === "true" ? JobTypes.FILE : JobTypes.OBSERVABLE;
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
    selectOptions: [JobTypes.FILE, JobTypes.OBSERVABLE],
  },
  {
    Header: "SubType",
    id: "type",
    accessor: (job) => job.observable_classification || job.file_mimetype,
    disableSortBy: true,
    maxWidth: 100,
    Filter: SelectOptionsFilter,
    selectOptions: Object.values(ObservableClassifications)
      .sort()
      .concat(Object.values(FileMimeTypes).sort()),
    Cell: ({ value }) => <TableCell value={value} />,
  },
  {
    Header: "TLP",
    id: "tlp",
    accessor: "tlp",
    Cell: ({ value }) => <TLPTag value={value} />,
    disableSortBy: true,
    Filter: SelectOptionsFilter,
    selectOptions: TlpChoices,
    maxWidth: 90,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: "tags",
    Cell: ({ value }) =>
      value.map((tag) => (
        <JobTag key={`jobtable-tags-${tag.label}`} tag={tag} className="ms-2" />
      )),
    disableSortBy: true,
    maxWidth: 100,
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Playbook Executed",
    id: "playbook_to_execute",
    accessor: (job) => job,
    Cell: ({ value: job }) => {
      /* Don't move from here!
      If playbooks is initialized in the top of the file is done before the loading in the table job
      and does not contain data */
      const { playbooks } = usePluginConfigurationStore.getState();
      const playbookResults =
        playbooks?.find((playbook) => playbook.id === job.playbook_to_execute)
          ?.name || "Custom Analysis";

      return (
        <div className="d-flex justify-content-between">
          <span className="d-block text-truncate">
            <CopyToClipboardButton showOnHover text={playbookResults}>
              {playbookResults}
            </CopyToClipboardButton>
          </span>
          <PlaybookInfoPopoverIcon job={job} />
        </div>
      );
    },
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 180,
  },
  {
    Header: "Process Time (mm:ss)",
    id: "process_time",
    accessor: "process_time",
    Cell: ({ value }) => <span>{processTimeMMSS(value)}</span>,
    maxWidth: 125,
  },
  {
    Header: "Status",
    id: "status",
    accessor: "status",
    Cell: ({ value }) => <StatusTag status={value} />,
    disableSortBy: true,
    Filter: SelectOptionsFilter,
    selectOptions: Object.values(JobStatuses),
  },
];
