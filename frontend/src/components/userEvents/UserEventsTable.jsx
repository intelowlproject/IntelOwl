/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col, UncontrolledTooltip, Spinner } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import {
  useDebounceInput,
  SyncButton,
  TableHintIcon,
  useDataTable,
  Loader,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";

import { format, fromZonedTime } from "date-fns-tz";
import { datetimeFormatStr, localTimezone } from "../../constants/miscConst";
import { TimePicker } from "../common/TimePicker";
import { JsonEditor } from "../common/JsonEditor";

// constants
const toPassTableProps = {
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing time filter.</small>
    </>
  ),
  SubComponent: ({ row }) => (
    <div
      id={`userEvent-jsoninput-${row.id}`}
      style={{ maxHeight: "50vh", width: "100%", overflow: "scroll" }}
      className="row"
    >
      <JsonEditor
        id="user_report_json"
        initialJsonData={{
          id: row.original.id,
          analyzable:
            row.original?.analyzable?.name || row.original?.analyzables,
          user: row.original.user,
          decay: row.original.decay,
          decay_progression: row.original.decay_progression,
          decay_timedelta_days: row.original.decay_timedelta_days,
          next_decay: row.original.next_decay,
          decay_times: row.original.decay_times,
          data_model: row.original.data_model,
        }}
        width="100%"
        readOnly
      />
    </div>
  ),
  config: { enableExpanded: true, enableFlexLayout: true },
};

export function UserEventsTable({
  title,
  url,
  columns,
  description,
  searchFromDateValue,
  searchToDateValue,
}) {
  // page title
  useTitle("IntelOwl | User Evaluations History", { restoreOnUnmount: true });

  const [
    data,
    tableNode,
    refetch,
    tableStateReducer,
    loadingTable,
    tableState,
  ] = useDataTable(
    {
      url,
    },
    {
      ...toPassTableProps,
      columns,
    },
  );

  // state
  const [fromDateType, setFromDateType] = React.useState(searchFromDateValue);
  const [toDateType, setToDateType] = React.useState(searchToDateValue);

  const onChangeFilter = ({ name, value }) => {
    const { filters } = tableState;
    // check if there is already a filter for the selected item
    const filterIndex = filters.findIndex((filter) => filter.id === name);
    let valueToChange = value;
    if (["event_date__gte", "event_date__lte"].includes(name))
      valueToChange = format(value, datetimeFormatStr);

    // If the filter is already present (index>=0) I update the value
    if (filterIndex !== -1) {
      // Note: this check is required to avoid infinite loop
      if (filters[filterIndex].value === valueToChange) return null;
      filters[filterIndex].value = value;
    }
    // otherwise I add a new element to the filter list
    else filters.push({ id: name, value });
    // set new filters
    return tableStateReducer({ filters }, { type: "setFilter" });
  };

  // this update the value after some times, this give user time to pick the datetime
  useDebounceInput(
    {
      name: "event_date__gte",
      value: fromZonedTime(fromDateType, localTimezone).toISOString(),
    },
    1000,
    onChangeFilter,
  );
  useDebounceInput(
    {
      name: "event_date__lte",
      value: fromZonedTime(toDateType, localTimezone).toISOString(),
    },
    1000,
    onChangeFilter,
  );

  return (
    <Loader
      loading={loadingTable}
      render={() => (
        <Container fluid>
          {/* Basic */}
          <Row className="mb-2">
            <Col className="d-flex align-items-center" sm={7}>
              <h1 id="UserEventsHistory">
                {title}&nbsp;
                <small className="text-gray">{data?.count} total</small>
              </h1>
              <div className="ms-2">
                <MdInfoOutline id="usereventstable-infoicon" fontSize="20" />
                <UncontrolledTooltip
                  trigger="hover"
                  target="usereventstable-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  {description}
                </UncontrolledTooltip>
              </div>
            </Col>
            <Col className="align-self-center">
              <TimePicker
                id="usereventstable__time-picker"
                fromName="event_date__gte"
                toName="event_date__lte"
                fromValue={fromDateType}
                toValue={toDateType}
                fromOnChange={setFromDateType}
                toOnChange={setToDateType}
              />
            </Col>
          </Row>
          {/* Actions */}
          <div className="px-3 bg-dark d-flex justify-content-end align-items-center">
            <TableHintIcon />
            <SyncButton onClick={refetch} className="ms-auto m-0 py-1" />
          </div>
          <div style={{ height: "80vh", overflowY: "scroll" }}>
            {/* Table */}
            {loadingTable ? <Spinner /> : tableNode}
          </div>
        </Container>
      )}
    />
  );
}
