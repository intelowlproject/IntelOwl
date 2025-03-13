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
import { TimePicker } from "../../common/TimePicker";

import { JOB_BASE_URI } from "../../../constants/apiURLs";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { useTimePickerStore } from "../../../stores/useTimePickerStore";
import { datetimeFormatStr } from "../../../constants/miscConst";

// component
export default function JobsTable() {
  console.debug("JobsTable rendered!");

  // page title
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const startTimeParam = searchParams.get("start-time");
  const endTimeParam = searchParams.get("end-time");

  console.debug("searchParams: ");

  const [toDateValue, fromDateValue, updateToDate, updateFromDate] =
    useTimePickerStore((state) => [
      state.toDateValue,
      state.fromDateValue,
      state.updateToDate,
      state.updateFromDate,
    ]);
  const [searchFromDateValue, setSearchFromDateValue] =
    React.useState(fromDateValue);
  const [searchToDateValue, setSearchToDateValue] = React.useState(toDateValue);

  // state
  const [areParamsInitialized, setAreParamsInitialized] = React.useState(false); // used to prevent a request with wrong params

  // this update the value after some times, this give user time to pick the datetime
  useDebounceInput(fromDateValue, 1000, setSearchFromDateValue);
  useDebounceInput(toDateValue, 1000, setSearchToDateValue);

  React.useEffect(() => {
    // update timepicker store with url params
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
      updateFromDate(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
      updateToDate(toDate(endTimeParam));
    }
    setAreParamsInitialized(true);
  }, [startTimeParam, endTimeParam, updateFromDate, updateToDate]);

  React.useEffect(() => {
    // After the initialization each time the time picker change, update the url
    // Note: this check is required to avoid infinite loop (url update time picker and time picker update url)
    if (areParamsInitialized) {
      if (
        startTimeParam !== format(searchFromDateValue, datetimeFormatStr) ||
        endTimeParam !== format(searchToDateValue, datetimeFormatStr)
      ) {
        const currentParams = {};
        // @ts-ignore
        searchParams.entries().forEach((element) => {
          const [paramName, paramValue] = element;
          currentParams[paramName] = paramValue;
        });
        setSearchParams({
          ...currentParams,
          "start-time": format(searchFromDateValue, datetimeFormatStr),
          "end-time": format(searchToDateValue, datetimeFormatStr),
        });
      }
    }
  }, [
    setSearchParams,
    areParamsInitialized,
    searchFromDateValue,
    searchToDateValue,
    startTimeParam,
    endTimeParam,
    searchParams,
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

  const [data, tableNode, refetch, _, loadingTable] = useDataTable(
    {
      url: JOB_BASE_URI,
      params: {
        received_request_time__gte: searchFromDateValue,
        received_request_time__lte: searchToDateValue,
      },
      initialParams: {
        ordering: "-start_time",
      },
    },
    toPassTableProps,
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
              <TimePicker />
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
