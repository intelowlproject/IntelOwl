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

import { useSearchParams } from "react-router-dom";
import { format, toDate } from "date-fns-tz";
import { USER_EVENT_ANALYZABLE } from "../../constants/apiURLs";
import { userReportsTableColumns } from "./userReportsTableColumns";
import { datetimeFormatStr } from "../../constants/miscConst";
import { TimePicker } from "../common/TimePicker";
import { JsonEditor } from "../common/JsonEditor";

// constants
const toPassTableProps = {
  columns: userReportsTableColumns,
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing time filter.</small>
    </>
  ),
  SubComponent: ({ row }) => (
    <div
      id={`userreport-jsoninput-${row.id}`}
      style={{ maxHeight: "50vh", width: "100%", overflow: "scroll" }}
      className="row"
    >
      <JsonEditor
        id="user_report_json"
        initialJsonData={{
          report: row.original,
        }}
        width="100%"
        readOnly
      />
    </div>
  ),
  config: { enableExpanded: true, enableFlexLayout: true },
};

// component
export default function UserReportsTable() {
  console.debug("UserReportsTable rendered!");

  // page title
  useTitle("IntelOwl | User Reports History", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const startTimeParam = searchParams.get("date__gte");
  const endTimeParam = searchParams.get("date__lte");

  // default: 24h
  const defaultFromDate = new Date();
  defaultFromDate.setDate(defaultFromDate.getDate() - 1);
  const [searchFromDateValue, setSearchFromDateValue] =
    React.useState(defaultFromDate);
  const [searchToDateValue, setSearchToDateValue] = React.useState(new Date());

  // state
  const [areParamsInitialized, setAreParamsInitialized] = React.useState(false); // used to prevent a request with wrong params

  React.useEffect(() => {
    // update filter with url params
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
    }
    setAreParamsInitialized(true);
  }, [startTimeParam, endTimeParam]);

  React.useEffect(() => {
    // After the initialization each time the time picker change or the filter, update the url
    // Note: this check is required to avoid infinite loop (url update time picker and time picker update url)
    if (
      areParamsInitialized &&
      (startTimeParam !== format(searchFromDateValue, datetimeFormatStr) ||
        endTimeParam !== format(searchToDateValue, datetimeFormatStr))
    ) {
      const currentParams = {};
      // @ts-ignore
      searchParams.entries().forEach((element) => {
        const [paramName, paramValue] = element;
        currentParams[paramName] = paramValue;
      });
      setSearchParams({
        ...currentParams,
        date__gte: format(searchFromDateValue, datetimeFormatStr),
        date__lte: format(searchToDateValue, datetimeFormatStr),
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    setSearchParams,
    areParamsInitialized,
    searchFromDateValue,
    searchToDateValue,
  ]);

  return areParamsInitialized ? ( // this "if" avoid one request
    <UserReportsTableComponent
      searchFromDateValue={searchFromDateValue}
      searchToDateValue={searchToDateValue}
    />
  ) : (
    <Spinner />
  );
}

function UserReportsTableComponent({ searchFromDateValue, searchToDateValue }) {
  const [
    data,
    tableNode,
    refetch,
    tableStateReducer,
    loadingTable,
    tableState,
  ] = useDataTable(
    {
      url: USER_EVENT_ANALYZABLE,
    },
    toPassTableProps,
  );

  // state
  const [fromDateType, setFromDateType] = React.useState(searchFromDateValue);
  const [toDateType, setToDateType] = React.useState(searchToDateValue);

  const onChangeFilter = ({ name, value }) => {
    const { filters } = tableState;
    // check if there is already a filter for the selected item
    const filterIndex = filters.findIndex((filter) => filter.id === name);
    let valueToChange = value;
    if (["date__gte", "date__lte"].includes(name))
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
    { name: "date__gte", value: fromDateType },
    1000,
    onChangeFilter,
  );
  useDebounceInput(
    { name: "date__lte", value: toDateType },
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
            <Col className="d-flex align-items-center" sm={5}>
              <h1 id="UserReportsHistory">
                User Reports History&nbsp;
                <small className="text-gray">{data?.count} total</small>
              </h1>
              <div className="ms-2">
                <MdInfoOutline id="userreportstable-infoicon" fontSize="20" />
                <UncontrolledTooltip
                  trigger="hover"
                  target="userreportstable-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  TO DO
                </UncontrolledTooltip>
              </div>
            </Col>
            <Col className="align-self-center">
              <TimePicker
                id="userreportstable__time-picker"
                fromName="date__gte"
                toName="date__lte"
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
