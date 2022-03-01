import React from "react";
import { Container, Row } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import {
  ElasticTimePicker,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useTimePickerStore
} from "@certego/certego-ui";

import { JOB_BASE_URI } from "../../../constants/api";
import { jobTableColumns } from "./data";

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
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true, });

  // consume zustand store
  const { range, fromTimeIsoStr, onTimeIntervalChange, } = useTimePickerStore();

  // API/ Table
  const [data, tableNode, refetch] = useDataTable(
    {
      url: JOB_BASE_URI,
      params: {
        received_request_time__gte: fromTimeIsoStr,
      },
      initialParams: {
        ordering: "-received_request_time",
      },
    },
    toPassTableProps
  );

  return (
    <Container fluid>
      {/* Basic */}
      <Row className="d-flex-start-center flex-column flex-lg-row mb-2">
        <h1>
          Jobs History&nbsp;
          <small className="text-muted">{data?.count} total</small>
        </h1>
        <ElasticTimePicker
          className="ml-auto"
          size="sm"
          defaultSelected={range}
          onChange={onTimeIntervalChange}
        />
      </Row>
      {/* Actions */}
      <Row className="px-3 bg-dark d-flex justify-content-end align-items-center">
        <TableHintIcon />
        <SyncButton onClick={refetch} className="ml-auto m-0 py-1" />
      </Row>
      {/* Table */}
      <Row>{tableNode}</Row>
    </Container>
  );
}
