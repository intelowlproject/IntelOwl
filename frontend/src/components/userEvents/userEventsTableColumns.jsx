/* eslint-disable react/prop-types */
import React from "react";

import { DefaultColumnFilter, DateHoverable } from "@certego/certego-ui";

import { LastEvaluationComponent } from "../common/engineBadges";
import { UserEventDecay } from "./UserEventDecay";
import TableCell from "../common/TableCell";
import TagsCell from "../common/TagsCell";

export const userEventsTableStartColumns = [
  {
    Header: () => "ID", // No header
    id: "id",
    accessor: "id",
    maxWidth: 65,
    disableSortBy: true,
    Cell: ({ value: id }) => (
      <div
        className="d-flex flex-column justify-content-center py-2"
        id={`user-report-${id}`}
      >
        #{id}
      </div>
    ),
    Filter: DefaultColumnFilter,
  },
  {
    Header: "Date",
    id: "date",
    accessor: "data_model.date",
    Cell: ({ value }) => (
      <div className="py-2">
        <DateHoverable ago value={value} format="hh:mm:ss a MMM do, yyyy" />
      </div>
    ),
    maxWidth: 100,
  },
  {
    Header: "User",
    id: "username",
    accessor: "user",
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-user__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 100,
  },
];

export const userEventsTableEndColumns = [
  {
    Header: "Evaluation",
    id: "evaluation",
    accessor: (userEvent) => userEvent.data_model,
    Cell: ({ value: dataModel, row }) =>
      dataModel.evaluation ? (
        <div className="d-flex justify-content-center py-2">
          <LastEvaluationComponent
            id={row.id}
            reliability={dataModel.reliability}
            evaluation={dataModel.evaluation}
          />
        </div>
      ) : (
        <div />
      ),
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    Header: "Decay",
    id: "next_decay",
    accessor: (userEvent) => userEvent,
    Cell: ({ value: userEvent }) => (
      <UserEventDecay
        decay={userEvent.next_decay}
        reliability={userEvent.data_model.reliability}
      />
    ),
    maxWidth: 100,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: (userEvent) => userEvent.data_model.tags,
    Cell: ({ value: tags, row }) => <TagsCell values={tags} rowId={row.id} />,
    disableSortBy: true,
    maxWidth: 100,
  },
  {
    disableSortBy: true,
    maxWidth: 160,
  },
  {
    Header: "Actions",
    id: "actions",
    accessor: "user",
    disableSortBy: true,
    Cell: ({ row: { original } }) => {
      // Import dynamically to avoid circular dependencies in column definition file
      const { useAuthStore } = require("../../stores/useAuthStore");
      const { IconButton } = require("@certego/certego-ui");
      const { MdDelete } = require("react-icons/md");
      const { deleteUserEvent } = require("./userEventsApi");

      const currentUser = useAuthStore((state) => state.user?.username);

      if (original.user === currentUser) {
        return (
          <div className="d-flex justify-content-center py-2">
            <IconButton
              id={`delete-user-event-${original.id}`}
              Icon={MdDelete}
              size="sm"
              color="danger"
              title="Delete evaluation"
              titlePlacement="top"
              onClick={async (e) => {
                e.stopPropagation();
                try {
                  const { AnalyzableHistoryTypes } = require("../../../constants/miscConst");
                  let type = AnalyzableHistoryTypes.USER_EVENT;
                  if (original.analyzables_name) type = AnalyzableHistoryTypes.USER_DOMAIN_WILDCARD_EVENT;
                  if (original.start_ip) type = AnalyzableHistoryTypes.USER_IP_WILDCARD_EVENT;

                  await deleteUserEvent(original.id, type);
                  window.location.reload();
                } catch (err) {
                  console.error(err);
                }
              }}
            />
          </div>
        );
      }
      return <div />;
    },
    maxWidth: 80,
  },
];


export const userAnalyzableEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Artifact",
    id: "analyzable_name",
    accessor: (userEvent) => userEvent?.analyzable?.name,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-analyzable__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 160,
  },
  ...userEventsTableEndColumns,
];

export const userDomainWildcardEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Query",
    id: "analyzables_name",
    accessor: (userEvent) => userEvent?.query,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-query__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 160,
  },
  ...userEventsTableEndColumns,
];

export const userIpWildcardEventsTableColumns = [
  ...userEventsTableStartColumns,
  {
    Header: "Network",
    id: "ip",
    accessor: (userEvent) => userEvent,
    Cell: ({ value, row }) => (
      <TableCell
        id={`table-cell-network__${row?.id}`}
        isCopyToClipboard
        isTruncate
        value={`${value.start_ip} - ${value.end_ip}`}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 140,
  },
  ...userEventsTableEndColumns,
];
