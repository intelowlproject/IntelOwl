/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col, UncontrolledTooltip } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import {
  ElasticTimePicker,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useTimePickerStore,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";

import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { investigationTableColumns } from "./investigationTableColumns";

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

  // consume zustand store
  const { range, fromTimeIsoStr, onTimeIntervalChange } = useTimePickerStore();

  // state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // API/ Table
  const [data, tableNode, refetch, _, loadingTable] = useDataTable(
    {
      url: INVESTIGATION_BASE_URI,
      params: {
        start_time__gte: fromTimeIsoStr,
      },
      initialParams: {
        ordering: "-start_time",
      },
    },
    toPassTableProps,
  );

  React.useEffect(() => {
    if (!loadingTable) setInitialLoading(false);
  }, [loadingTable]);

  React.useEffect(() => {
    if (!initialLoading) refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialLoading]);

  return (
    <Container fluid>
      {/* Basic */}
      <Row className="mb-2">
        <Col className="d-flex align-items-center">
          <h1 id="investigationHistory">
            Investigations History&nbsp;
            <small className="text-gray">{data?.count} total</small>
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
      <div style={{ height: "80vh", overflowY: "scroll" }}>
        {/* Table */}
        {tableNode}
      </div>
    </Container>
  );
}
