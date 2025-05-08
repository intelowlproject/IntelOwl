/* eslint-disable react/prop-types */
import React from "react";

import {
  DefaultColumnFilter,
  DateHoverable,
  CopyToClipboardButton,
} from "@certego/certego-ui";

// const mockData = [{
//   'id': 6,
//   'user': {
//     'username': 'user',
//     'profile': {
//       'user': {
//         'username': 'user',
//         'email': 'user@intelowl.com',
//         'first_name': '',
//         'last_name': '',
//         'password': 'test',
//         'is_active': true
//       },
//       'company_name': '',
//       'company_role': '',
//       'twitter_handle': '',
//       'discover_from': 'other',
//       'task_priority': 10,
//       'is_robot': false
//     }},
//     'date': '2025-05-07T14:11:25.071686Z',
//     'next_decay': '2025-05-10T14:11:25.071686Z',
//     'decay_times': 0,
//     'analyzable': 4,
//     'data_model': {
//       'id': 6,
//       'analyzers_report': [],
//       'ietf_report': [],
//       'evaluation': 'malicious',
//       'reliability': 8,
//       'kill_chain_phase': null,
//       'external_references': [],
//       'related_threats': [],
//       'tags': null,
//       'malware_family': null,
//       'additional_info': {},
//       'date': '2025-05-07T14:11:25.071235Z',
//       'rank': null,
//       'resolutions': []
//     },
//     'data_model_object_id': 6,
//     'decay_progression': 0,
//     'decay_timedelta_days': 3,
//     'data_model_content_type': 44
//   }]

export const userReportsTableColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 75,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div
        className="d-flex flex-column justify-content-center"
        id={`user-report-${id}`}
      >
        #{id}
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Created",
    id: "date",
    accessor: "date",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user.username",
    Cell: ({ value, row: { original: report } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-user-${report?.id}`}
        key={`table-user-${report?.id}`}
        text={value}
        className="d-block text-truncate"
      >
        {value}
      </CopyToClipboardButton>
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 120,
  },
  {
    Header: "Analyzable",
    id: "analyzable",
    accessor: "analyzable",
    Cell: ({ value, row: { original: report } }) => (
      <CopyToClipboardButton
        showOnHover
        id={`table-analyzable-${report?.id}`}
        key={`table-analyzable-${report?.id}`}
        text={value}
        className="d-block text-truncate"
      >
        {value}
      </CopyToClipboardButton>
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 200,
  },
  {
    Header: "Decay",
    id: "next_decay",
    accessor: "next_decay",
    Cell: ({ value }) => (
      <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
    ),
    maxWidth: 100,
  },
  {
    Header: "Description",
    id: "description",
    accessor: (report) => report,
    Cell: ({ value: report }) => <div>{report}</div>,
    disableSortBy: true,
    disableFilter: true,
    maxWidth: 280,
  },
];
