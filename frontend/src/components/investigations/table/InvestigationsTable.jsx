/* eslint-disable react/prop-types */
import React from "react";
import {
  Container,
  Row,
  Col,
  UncontrolledTooltip,
  Label,
  Input,
  Spinner,
} from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import axios from "axios";

import { useDebounceInput, DataTable } from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";

import { useSearchParams } from "react-router-dom";
import { format, toDate } from "date-fns-tz";
import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { investigationTableColumns } from "./investigationTableColumns";
import { TimePicker } from "../../common/TimePicker";
import { useTimePickerStore } from "../../../stores/useTimePickerStore";
import { datetimeFormatStr } from "../../../constants/miscConst";

// constants
const toPassTableProps = {
  columns: investigationTableColumns,
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing time filter.</small>
    </>
  ),
};

// component
export default function InvestigationsTable() {
  console.debug("InvestigationsTable rendered!");

  // page title
  useTitle("IntelOwl | Investigation History", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const analyzedObjectNameParam =
    searchParams.get("analyzed-object-name") || "";
  const startTimeParam = searchParams.get("start-time");
  const endTimeParam = searchParams.get("end-time");

  // store
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
  /* searchNameType is used to show the user typed text (this state changes for each char typed), 
  searchNameRequest is used in the request to the backend and it's update periodically.
  In this way we avoid a request for each char. */
  const [searchNameType, setSearchNameType] = React.useState("");
  const [searchNameRequest, setSearchNameRequest] = React.useState("");

  useDebounceInput(fromDateValue, 1000, setSearchFromDateValue);
  useDebounceInput(toDateValue, 1000, setSearchToDateValue);
  useDebounceInput(searchNameType, 1000, setSearchNameRequest);

  React.useEffect(() => {
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
      updateFromDate(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
      updateToDate(toDate(endTimeParam));
    }
    if (analyzedObjectNameParam) setSearchNameType(analyzedObjectNameParam);
    if (analyzedObjectNameParam) setSearchNameRequest(analyzedObjectNameParam);
    setParamInitialization(true);
  }, [
    analyzedObjectNameParam,
    startTimeParam,
    endTimeParam,
    updateFromDate,
    updateToDate,
  ]);

  React.useEffect(() => {
    // this check is to avoid to send request and compare state and url params before we initialized the state
    if (paramInitialization) {
      if (
        startTimeParam !== format(searchFromDateValue, datetimeFormatStr) ||
        endTimeParam !== format(searchToDateValue, datetimeFormatStr) ||
        analyzedObjectNameParam !== searchNameRequest
      ) {
        setSearchParams({
          "start-time": format(searchFromDateValue, datetimeFormatStr),
          "end-time": format(searchToDateValue, datetimeFormatStr),
          "analyzed-object-name": searchNameRequest,
        });
      }
      let investigationList = [];
      let pageNumber = 0;
      const params = {
        start_time__gte: searchFromDateValue,
        start_time__lte: searchToDateValue,
        analyzed_object_name: searchNameRequest,
      };
      axios
        .get(INVESTIGATION_BASE_URI, { params })
        .then((response) => {
          investigationList = investigationList.concat(response.data.results);
          pageNumber = Math.min(response.data.total_pages, 10);
          const additionalRequests = [];
          // eslint-disable-next-line no-plusplus
          for (let page = 2; page <= pageNumber; page++) {
            params.page = page;
            additionalRequests.push(
              axios.get(INVESTIGATION_BASE_URI, { params }),
            );
          }
          // Promise.all works only if ALL the requests are done successfully
          return Promise.allSettled(additionalRequests);
        })
        .then((responseList) => {
          // We need to handle promise manually to exclude failed requests
          responseList
            .filter((response) => response.status === "fulfilled")
            .forEach((successfulResponse) => {
              investigationList = investigationList.concat(
                successfulResponse.value.data.results,
              );
            });
          setData({
            results: investigationList,
            count: investigationList.length,
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
    searchNameRequest,
    startTimeParam,
    endTimeParam,
    analyzedObjectNameParam,
  ]);

  return (
    <Container fluid>
      {/* Basic */}
      <Row className="mb-2">
        <Col className="d-flex align-items-center" sm={5}>
          <h1 id="investigationHistory">
            Investigations History&nbsp;
            <small className="text-gray">{data.count} total</small>
          </h1>
          <div className="ms-2">
            <MdInfoOutline id="investigationstable-infoicon" fontSize="20" />
            <UncontrolledTooltip
              trigger="hover"
              target="investigationstable-infoicon"
              placement="right"
              fade={false}
              innerClassName="p-2 text-start text-nowrap md-fit-content"
            >
              Investigations are a framework to connect jobs with each other,
              correlate the findings and collaborate with teammates to reach
              common goals.
            </UncontrolledTooltip>
          </div>
        </Col>
        <Col className="align-self-center">
          <TimePicker />
          <div className="d-flex float-end me-1">
            <div className="d-flex align-items-center">
              <Label check>Name</Label>
              <div className="ms-1 d-flex">
                <MdInfoOutline
                  id="investigationstable-name-info"
                  fontSize="15"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  target="investigationstable-name-info"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Filter investigations showing only the ones that contain at
                  least one job related to an analyzable with this name.
                </UncontrolledTooltip>
              </div>
              <Label check className="me-1">
                :
              </Label>
              <Input
                id="nameSearch"
                type="text"
                onChange={(event) => setSearchNameType(event.target.value)}
                value={searchNameType}
              />
            </div>
          </div>
        </Col>
      </Row>
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
  );
}
