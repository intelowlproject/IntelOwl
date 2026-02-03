/* eslint-disable react/prop-types */
import React from "react";
import { UncontrolledTooltip } from "reactstrap";

import {
  DateHoverable,
  DefaultColumnFilter,
  SelectOptionsFilter,
} from "@certego/certego-ui";
import { format } from "date-fns-tz";

import TableCell from "../../common/TableCell";
import TagsCell from "../../common/TagsCell";
import { LastEvaluationComponent } from "../../common/engineBadges";
import {
  JobResultSections,
  AnalyzableHistoryTypes,
  HistoryPages,
  datetimeFormatStr,
} from "../../../constants/miscConst";

export const analyzablesHistoryTableColumns = [
  {
    Header: "ID",
    id: "pk",
    accessor: "id",
    Cell: ({ value: id, row: { original } }) => {
      const fromDate = new Date(original.date);
      fromDate.setDate(fromDate.getDate() - 1);
      return (
        <div className="d-flex flex-column justify-content-center p-2">
          <div>
            <a
              id={`analyzable-history__${original.type}-${id}`}
              href={
                original.type === AnalyzableHistoryTypes.JOB
                  ? `/jobs/${id}/${JobResultSections.VISUALIZER}`
                  : `/history/${
                      HistoryPages[
                        Object.keys(AnalyzableHistoryTypes).find(
                          (key) =>
                            AnalyzableHistoryTypes[key] === original.type,
                        )
                      ]
                    }?event_date__gte=${encodeURIComponent(
                      format(fromDate, datetimeFormatStr),
                    )}&event_date__lte=${encodeURIComponent(
                      format(new Date(), datetimeFormatStr),
                    )}&ordering=-date&id=${id}`
              }
              target="_blank"
              rel="noreferrer"
            >
              #{id}
            </a>
            <UncontrolledTooltip
              target={`analyzable-history__${original.type}-${id}`}
              placement="top"
              fade={false}
            >
              {original.type.replace("_", " ")} overview
            </UncontrolledTooltip>
          </div>
        </div>
      );
    },
    disableSortBy: true,
    maxWidth: 60,
    Filter: DefaultColumnFilter,
  },
  {
    Header: "User",
    id: "user",
    accessor: "user",
    Cell: ({ value, row: { original } }) => (
      <TableCell
        id={`table-cell-user__${original.id}`}
        isCopyToClipboard
        isTruncate
        value={value}
      />
    ),
    disableSortBy: true,
    Filter: DefaultColumnFilter,
    maxWidth: 90,
  },
  {
    Header: "Date",
    id: "date",
    accessor: (analyzable) => analyzable.data_model.date,
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
    Header: "Type",
    id: "type",
    accessor: "type",
    disableSortBy: true,
    maxWidth: 90,
    Filter: SelectOptionsFilter,
    selectOptions: Object.values(AnalyzableHistoryTypes),
    Cell: ({ value, row: { original } }) => (
      <TableCell
        id={`table-cell-type__${original.id}`}
        value={value.replaceAll("_", " ")}
      />
    ),
  },
  {
    Header: "Evaluation",
    id: "evaluation",
    accessor: (analyzable) => analyzable.data_model,
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
    maxWidth: 120,
  },
  {
    Header: "Tags",
    id: "tags",
    accessor: "data_model.tags",
    Cell: ({ value, row }) => <TagsCell values={value} rowId={row.id} />,
    disableSortBy: true,
    maxWidth: 100,
    Filter: DefaultColumnFilter,
    filterValueAccessorFn: (tags) => tags.map((tag) => tag.label),
  },
  {
    Header: "Description",
    id: "descriptions",
    accessor: (value) => {
      let text = "";
      if (value.type === AnalyzableHistoryTypes.JOB && value.playbook) {
        text = `Playbook executed: ${value.playbook}`;
      } else if (value.type === AnalyzableHistoryTypes.JOB) {
        text = "Custom Analysis";
      } else {
        text = value.reason;
      }
      return text;
    },
    disableSortBy: true,
    Cell: ({ value, row }) =>
      value && (
        <TableCell
          id={`table-cell-description__${row.id}`}
          isCopyToClipboard
          isTruncate
          value={value}
        />
      ),
    minWidth: 200,
  },
];
