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

import {
  useDebounceInput,
  SyncButton,
  TableHintIcon,
  useDataTable,
  Loader,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";

import { format, fromZonedTime } from "date-fns-tz";
import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { investigationTableColumns } from "./investigationTableColumns";
import { datetimeFormatStr, localTimezone } from "../../../constants/miscConst";
import { TimePicker } from "../../common/TimePicker";

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

export function InvestigationTable({
  searchFromDateValue,
  searchToDateValue,
  searchNameRequest,
}) {
  // page title
  useTitle("IntelOwl | Investigation History", { restoreOnUnmount: true });

  const [
    data,
    tableNode,
    refetch,
    tableStateReducer,
    loadingTable,
    tableState,
  ] = useDataTable(
    {
      url: INVESTIGATION_BASE_URI,
      params: {
        analyzed_object_name: searchNameRequest,
      },
    },
    toPassTableProps,
  );

  // state
  const [searchNameType, setSearchNameType] = React.useState(searchNameRequest);
  const [fromDateType, setFromDateType] = React.useState(searchFromDateValue);
  const [toDateType, setToDateType] = React.useState(searchToDateValue);

  const onChangeFilter = ({ name, value }) => {
    const { filters } = tableState;
    // check if there is already a filter for the selected item
    const filterIndex = filters.findIndex((filter) => filter.id === name);
    let valueToChange = value;
    if (["start_time__gte", "start_time__lte"].includes(name))
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
      name: "start_time__gte",
      value: fromZonedTime(fromDateType, localTimezone).toISOString(),
    },
    1000,
    onChangeFilter,
  );
  useDebounceInput(
    {
      name: "start_time__lte",
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
            <Col className="d-flex align-items-center" sm={5}>
              <h1 id="investigationHistory">
                Investigations History&nbsp;
                <small className="text-gray">{data.count} total</small>
              </h1>
              <div className="ms-2">
                <MdInfoOutline
                  id="investigationstable-infoicon"
                  fontSize="20"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  target="investigationstable-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Investigations are a framework to connect jobs with each
                  other, correlate the findings and collaborate with teammates
                  to reach common goals.
                </UncontrolledTooltip>
              </div>
            </Col>
            <Col className="align-self-center">
              <TimePicker
                id="investigations-table__time-picker"
                fromName="start_time__gte"
                toName="start_time__lte"
                fromValue={fromDateType}
                toValue={toDateType}
                fromOnChange={setFromDateType}
                toOnChange={setToDateType}
              />
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
                      Filter investigations showing only the ones that contain
                      at least one job related to an analyzable with this name.
                    </UncontrolledTooltip>
                  </div>
                  <Label check className="me-1">
                    :
                  </Label>
                  <Input
                    id="nameSearch"
                    type="text"
                    onChange={(event) => {
                      setSearchNameType(event.target.value);
                      // if the user clears the filter
                      if (event.target.value.length === 0) {
                        // Set empty string to remove the filter
                        onChangeFilter({
                          name: "analyzed_object_name",
                          value: "",
                        });
                      }
                    }}
                    onKeyDown={(event) => {
                      // the request is sent if the user presses 'enter'
                      if (event.key === "Enter") {
                        onChangeFilter({
                          name: "analyzed_object_name",
                          value: event.target.value || "",
                        });
                      }
                    }}
                    onKeyUp={(event) => {
                      // if the user presses 'backspace'
                      // the request is sent if input value is empty
                      if (
                        event.key === "Backspace" &&
                        event.target.value.length === 0
                      ) {
                        // Set empy string to remove the filter
                        onChangeFilter({
                          name: "analyzed_object_name",
                          value: "",
                        });
                      }
                    }}
                    onPaste={(event) => {
                      // if copy-paste is done, the request is sent automatically
                      onChangeFilter({
                        name: "analyzed_object_name",
                        value: event.clipboardData.getData("text/plain") || "",
                      });
                    }}
                    value={searchNameType}
                  />
                </div>
              </div>
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
