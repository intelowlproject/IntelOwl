/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col, UncontrolledTooltip, Spinner } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import {
  Loader,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useDebounceInput,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";
import { useSearchParams } from "react-router-dom";
import { format, toDate } from "date-fns";
import { jobTableColumns } from "./jobTableColumns";

import { JOB_BASE_URI } from "../../../constants/apiURLs";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { datetimeFormatStr } from "../../../constants/miscConst";
import { TimePicker } from "../../common/TimePicker";

// component
export default function JobsTable() {
  console.debug("JobsTable rendered!");

  // page title
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const startTimeParam = searchParams.get("received_request_time__gte");
  const endTimeParam = searchParams.get("received_request_time__lte");

  // default: 24h
  const defaultFromDate = new Date();
  defaultFromDate.setDate(defaultFromDate.getDate() - 1);
  const [searchFromDateValue, setSearchFromDateValue] =
    React.useState(defaultFromDate);
  const [searchToDateValue, setSearchToDateValue] = React.useState(new Date());

  // state
  const [areParamsInitialized, setAreParamsInitialized] = React.useState(false); // used to prevent a request with wrong params

  React.useEffect(() => {
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
    }
    setAreParamsInitialized(true);
  }, [startTimeParam, endTimeParam]);

  React.useEffect(() => {
    // After the initialization each time the time picker change, update the url
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
        received_request_time__gte: format(
          searchFromDateValue,
          datetimeFormatStr,
        ),
        received_request_time__lte: format(
          searchToDateValue,
          datetimeFormatStr,
        ),
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
    <JobsTableComponent
      searchFromDateValue={searchFromDateValue}
      searchToDateValue={searchToDateValue}
    />
  ) : (
    <Spinner />
  );
}

// constants
const toPassTableProps = {
  columns: jobTableColumns,
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing time filter.</small>
    </>
  ),
};

function JobsTableComponent({ searchFromDateValue, searchToDateValue }) {
  const [playbooksLoading, playbooksError] = usePluginConfigurationStore(
    (state) => [state.playbooksLoading, state.playbooksError],
  );

  const [
    data,
    tableNode,
    refetch,
    tableStateReducer,
    loadingTable,
    tableState,
  ] = useDataTable(
    {
      url: JOB_BASE_URI,
      params: {
        ordering: "-received_request_time",
      },
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

    // If the filter is already present (index>=0) I update the value
    if (filterIndex !== -1) {
      // Note: this check is required to avoid infinite loop
      if (filters[filterIndex].value === format(value, datetimeFormatStr))
        return null;
      filters[filterIndex].value = value;
    }
    // otherwise I add a new element to the filter list
    else filters.push({ id: name, value });
    // set new filters
    return tableStateReducer({ filters }, { type: "setFilter" });
  };

  // this update the value after some times, this give user time to pick the datetime
  useDebounceInput(
    { name: "received_request_time__gte", value: fromDateType },
    1000,
    onChangeFilter,
  );
  useDebounceInput(
    { name: "received_request_time__lte", value: toDateType },
    1000,
    onChangeFilter,
  );

  return (
    // this loader is required to correctly get the name of the playbook executed
    <Loader
      loading={playbooksLoading || loadingTable}
      error={playbooksError}
      render={() => (
        <Container fluid>
          {/* Basic */}
          <Row className="mb-2">
            <Col className="d-flex align-items-center">
              <h1 id="jobsHistory">
                Jobs History&nbsp;
                <small className="text-gray">{data?.count} total</small>
              </h1>
              <div className="ms-2">
                <MdInfoOutline id="jobstable-infoicon" fontSize="20" />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 500 }}
                  target="jobstable-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Jobs are simple analysis of an observable or a file.
                </UncontrolledTooltip>
              </div>
            </Col>
            <Col className="align-self-center">
              <TimePicker
                id="jobs-table__time-picker"
                fromName="received_request_time__gte"
                toName="received_request_time__lte"
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
            {tableNode}
          </div>
        </Container>
      )}
    />
  );
}
