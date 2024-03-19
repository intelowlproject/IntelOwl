/* eslint-disable react/prop-types */
import React from "react";
import { Container, Row, Col } from "reactstrap";

import {
  Loader,
  ElasticTimePicker,
  SyncButton,
  TableHintIcon,
  useDataTable,
  useTimePickerStore,
} from "@certego/certego-ui";

import useTitle from "react-use/lib/useTitle";
import { jobTableColumns } from "./jobTableColumns";

import { JOB_BASE_URI } from "../../../constants/apiURLs";
import { useGuideContext } from "../../../contexts/GuideContext";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";

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
  const [playbooksLoading, playbooksError] = usePluginConfigurationStore(
    (state) => [state.playbooksLoading, state.playbooksError],
  );

  console.debug("JobsTable rendered!");

  // page title
  useTitle("IntelOwl | Jobs History", { restoreOnUnmount: true });

  // consume zustand store
  const { range, fromTimeIsoStr, onTimeIntervalChange } = useTimePickerStore();

  // state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // API/ Table
  const [data, tableNode, refetch, , loadingTable] = useDataTable(
    {
      url: JOB_BASE_URI,
      params: {
        received_request_time__gte: fromTimeIsoStr,
      },
      initialParams: {
        ordering: "-received_request_time",
      },
    },
    toPassTableProps,
  );

  React.useEffect(() => {
    if (!loadingTable) setInitialLoading(false);
  }, [loadingTable]);

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 7 });
      }, 100);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    if (!initialLoading) refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialLoading]);

  return (
    // this loader is required to correctly get the name of the playbook executed
    <Loader
      loading={playbooksLoading}
      error={playbooksError}
      render={() => (
        <Container fluid>
          {/* Basic */}
          <Row className="mb-2">
            <Col>
              <h1 id="jobsHistory">
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
          <div style={{ height: "80vh", overflowY: "scroll" }}>
            {/* Table */}
            {tableNode}
          </div>
        </Container>
      )}
    />
  );
}
