import React, { useEffect } from "react";
import { Container, Row, Col } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import {
  ElasticTimePicker,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useTimePickerStore,
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
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

  // consume zustand store
  const { range, fromTimeIsoStr, onTimeIntervalChange } = useTimePickerStore();

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

  useEffect(() => {
    refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Container fluid>
      {/* Basic */}
      <Row className="mb-2">
        <Col>
          <h1>
            Jobs History&nbsp;
            <small className="text-muted">{data?.count} total</small>
          </h1>
        </Col>
        <Col className="align-self-center">
          <ElasticTimePicker
            className="float-end"
            size="sm"
            defaultSelected={range}
            onChange={onTimeIntervalChange}
          />
        </Col>
      </Row>
      {/* Actions */}
      <div className="px-3 bg-dark d-flex justify-content-end align-items-center">
        <TableHintIcon />
        <SyncButton onClick={refetch} className="ms-auto m-0 py-1" />
      </div>
      {/* Table */}
      {tableNode}
    </Container>
  );
}
