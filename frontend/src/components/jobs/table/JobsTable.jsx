/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col, UncontrolledTooltip } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import { fromZonedTime } from "date-fns-tz";
import {
  Loader,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useDebounceInput,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";
import { format } from "date-fns";
import { jobTableColumns } from "./jobTableColumns";
import { JOB_BASE_URI } from "../../../constants/apiURLs";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { datetimeFormatStr, localTimezone } from "../../../constants/miscConst";
import { TimePicker } from "../../common/TimePicker";

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

export function JobsTable({ searchFromDateValue, searchToDateValue }) {
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

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
    {
      name: "received_request_time__gte",
      value: fromZonedTime(fromDateType, localTimezone).toISOString(),
    },
    1000,
    onChangeFilter,
  );
  useDebounceInput(
    {
      name: "received_request_time__lte",
      value: fromZonedTime(toDateType, localTimezone).toISOString(),
    },
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
