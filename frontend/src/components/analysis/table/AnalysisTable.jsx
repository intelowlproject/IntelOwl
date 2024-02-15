/* eslint-disable react/prop-types */
import React from "react";
import useAxios from "axios-hooks";
import { Container, Row, Col } from "reactstrap";

import {
  Loader,
  // ElasticTimePicker,
  SyncButton,
  TableHintIcon,
  //  useDataTable,
  //  useTimePickerStore,
  DataTable,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";

import { ANALYSIS_BASE_URI } from "../../../constants/apiURLs";
import { analysisTableColumns } from "./analysisTableColumns";

// constants
// const toPassTableProps = {
//     columns: analysisTableColumns,
//     tableEmptyNode: (
//       <>
//         <h4>No Data</h4>
//         <small className="text-muted">Note: Try changing time filter.</small>
//       </>
//     ),
//   };

// table config
const tableConfig = {
  tableEmptyNode: (
    <>
      <h4>No Data</h4>
      <small className="text-muted">Note: Try changing time filter.</small>
    </>
  ),
};
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "start_time", desc: true }],
};

// component
export default function AnalysisTable() {
  console.debug("AnalysisTable rendered!");

  // page title
  useTitle("IntelOwl | Analysis History", { restoreOnUnmount: true });

  // consume zustand store
  // const { range, fromTimeIsoStr,onTimeIntervalChange } = useTimePickerStore();

  const [{ data: analysis, loading, error }, refetch] = useAxios({
    url: ANALYSIS_BASE_URI,
  });
  console.debug(analysis);

  // API/ Table
  // const [data, tableNode, refetch] = useDataTable(
  //   {
  //     url: ANALYSIS_BASE_URI,
  //     initialParams: {
  //       page: "1",
  //     },
  //   },
  //   toPassTableProps,
  // );

  /* This useEffect cause an error in local development (axios CanceledError) because it is called twice.
    The first call is trying to update state asynchronously, 
    but the update couldn't happen when the component is unmounted

    Attention! we cannot remove it: this update the job list after the user start a new scan
  */
  React.useEffect(() => {
    refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Container fluid>
      {/* Basic */}
      <Row className="mb-2">
        <Col>
          <h1 id="analysisHistory">
            Analysis History&nbsp;
            <small className="text-muted">{analysis?.count} total</small>
          </h1>
        </Col>
        {/* <Col className="align-self-center">
              <ElasticTimePicker
                className="float-end"
                size="sm"
                defaultSelected={range}
                onChange={onTimeIntervalChange}
              />
            </Col> */}
      </Row>
      {/* Actions */}
      <div className="px-3 bg-dark d-flex justify-content-end align-items-center">
        <TableHintIcon />
        <SyncButton onClick={refetch} className="ms-auto m-0 py-1" />
      </div>
      <div style={{ height: "80vh", overflowY: "scroll" }}>
        {/* Table */}
        {/* {tableNode} */}
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <DataTable
              data={analysis.results}
              config={tableConfig}
              initialState={tableInitialState}
              columns={analysisTableColumns}
            />
          )}
        />
      </div>
    </Container>
  );
}
