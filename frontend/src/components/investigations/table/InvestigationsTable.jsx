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
import { toDate } from "date-fns-tz";
import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { investigationTableColumns } from "./investigationTableColumns";
import { TimePicker } from "../../common/TimePicker";
import { useTimePickerStore } from "../../../stores/useTimePickerStore";

// constants
const toPassProps = {
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
  const [searchParams] = useSearchParams();
  const analyzedObjectNameParam = searchParams.get("analyzed_object_name");
  const fromDateParam = searchParams.get("from");
  const toDateParam = searchParams.get("to");

  // page title
  useTitle("IntelOwl | Investigation History", { restoreOnUnmount: true });

  // store
  const [toDateValue, fromDateValue, updateToDate, updateFromDate] =
    useTimePickerStore((state) => [
      state.toDateValue,
      state.fromDateValue,
      state.updateToDate,
      state.updateFromDate,
    ]);

  // state
  const [loading, setILoading] = React.useState(true);
  const [data, setData] = React.useState({ results: [], count: 0 });
  /* searchNameType is used to show the user typed text (this state changes for each char typed), 
  searchNameRequest is used in the request to the backend and it's update periodically.
  In this way we avoid a request for each char. */
  const [searchNameType, setSearchNameType] = React.useState("");
  const [searchNameRequest, setSearchNameRequest] = React.useState("");
  useDebounceInput(searchNameType, 1000, setSearchNameRequest);

  React.useEffect(() => {
    console.debug("DEBUG");
    if (fromDateParam) updateFromDate(toDate(fromDateParam));
    if (toDateParam) updateToDate(toDate(toDateParam));
    if (analyzedObjectNameParam) setSearchNameType(analyzedObjectNameParam);
    if (analyzedObjectNameParam) setSearchNameRequest(analyzedObjectNameParam);
  }, [
    analyzedObjectNameParam,
    fromDateParam,
    toDateParam,
    updateFromDate,
    updateToDate,
  ]);

  React.useEffect(() => {
    axios
      .get(INVESTIGATION_BASE_URI, {
        params: {
          start_time__gte: fromDateValue,
          start_time__lte: toDateValue,
          analyzed_object_name: searchNameRequest,
        },
      })
      .then((response) => {
        setData(response.data);
        setILoading(false);
      });
  }, [fromDateValue, toDateValue, searchNameRequest]);

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
          <div className="d-flex float-end mx-2">
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
              <Label check className="me-2">
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
      {/* Actions */}
      {loading ? (
        <Spinner />
      ) : (
        <div style={{ height: "80vh", overflowY: "scroll" }}>
          <DataTable data={data.results} {...toPassProps} />
        </div>
      )}
    </Container>
  );
}
