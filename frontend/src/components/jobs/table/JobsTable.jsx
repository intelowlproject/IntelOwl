/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col, UncontrolledTooltip, Spinner } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import {
  DataTable,
  Loader,
  TableHintIcon,
  useDebounceInput,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";
import { useSearchParams } from "react-router-dom";
import { format, toDate } from "date-fns";
import axios from "axios";
import { jobTableColumns } from "./jobTableColumns";
import { TimePicker } from "../../common/TimePicker";

import { JOB_BASE_URI } from "../../../constants/apiURLs";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { useTimePickerStore } from "../../../stores/useTimePickerStore";
import { datetimeFormatStr } from "../../../constants/miscConst";

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

// component
export default function JobsTable() {
  console.debug("JobsTable rendered!");

  // page title
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const startTimeParam = searchParams.get("start-time");
  const endTimeParam = searchParams.get("end-time");

  const [playbooksLoading, playbooksError] = usePluginConfigurationStore(
    (state) => [state.playbooksLoading, state.playbooksError],
  );

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
  const [paramInitialization, setParamInitialization] = React.useState(false); // used to prevent a request with wrong params
  const [loading, setLoading] = React.useState(true);
  const [data, setData] = React.useState({
    results: [],
    count: 0,
    total_pages: 0,
  });

  // this update the value after some times, this give user time to pick the datetime
  useDebounceInput(fromDateValue, 1000, setSearchFromDateValue);
  useDebounceInput(toDateValue, 1000, setSearchToDateValue);

  React.useEffect(() => {
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
      updateFromDate(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
      updateToDate(toDate(endTimeParam));
    }
    setParamInitialization(true);
  }, [startTimeParam, endTimeParam, updateFromDate, updateToDate]);

  React.useEffect(() => {
    // this check is to avoid to send request and compare state and url params before we initialized the state
    if (paramInitialization) {
      if (
        startTimeParam !== format(searchFromDateValue, datetimeFormatStr) ||
        endTimeParam !== format(searchToDateValue, datetimeFormatStr)
      ) {
        setSearchParams({
          "start-time": format(searchFromDateValue, datetimeFormatStr),
          "end-time": format(searchToDateValue, datetimeFormatStr),
        });
      }
      let jobList = [];
      let pageNumber = 0;
      const params = {
        received_request_time__gte: searchFromDateValue,
        received_request_time__lte: searchToDateValue,
      };
      axios
        .get(JOB_BASE_URI, { params })
        .then((response) => {
          jobList = jobList.concat(response.data.results);
          pageNumber = Math.min(response.data.total_pages, 10);
          const additionalRequests = [];
          // eslint-disable-next-line no-plusplus
          for (let page = 2; page <= pageNumber; page++) {
            params.page = page;
            additionalRequests.push(axios.get(JOB_BASE_URI, { params }));
          }
          // Promise.all works only if ALL the requests are done successfully
          return Promise.allSettled(additionalRequests);
        })
        .then((responseList) => {
          // We need to handle promise manually to exclude failed requests
          responseList
            .filter((response) => response.status === "fulfilled")
            .forEach((successfulResponse) => {
              jobList = jobList.concat(successfulResponse.value.data.results);
            });
          setData({
            results: jobList,
            count: jobList.length,
            total_pages: pageNumber,
          });
          setLoading(false);
        });
    }
  }, [
    setSearchParams,
    paramInitialization,
    searchFromDateValue,
    searchToDateValue,
    startTimeParam,
    endTimeParam,
  ]);

  return (
    // this loader is required to correctly get the name of the playbook executed
    <Loader
      loading={playbooksLoading}
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
          </div>
          {/* Table */}
          {loading ? (
            <Spinner />
          ) : (
            <div style={{ height: "80vh", overflowY: "scroll" }}>
              <DataTable
                data={data.results}
                pageCount={data.total_pages}
                {...toPassTableProps}
              />
            </div>
          )}
        </Container>
      )}
    />
  );
}
