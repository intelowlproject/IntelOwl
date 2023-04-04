import React from "react";
import PropTypes from "prop-types";
import { Container, Col, Row } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import {
  Loader,
  ContentSection,
  DataTable,
  TableHintIcon,
  SyncButton,
  ButtonSelect,
} from "@certego/certego-ui";

import { PluginInfoCard } from "./utils";
import {
  useOrganizationStore,
  usePluginConfigurationStore,
} from "../../../stores";

// table config
const tableConfig = {};
const tableInitialState = {
  pageSize: 6,
  sortBy: [{ id: "name", desc: false }],
};
function TableBodyComponent({ page }) {
  return (
    <ContentSection className="bg-body d-flex flex-wrap">
      {page.map((row) => (
        <Col md={6} lg={4} className="mt-2">
          <PluginInfoCard pluginInfo={row?.original} />
        </Col>
      ))}
    </ContentSection>
  );
}

export default function PluginWrapper({
  heading,
  description,
  stateSelector,
  columns,
  type,
}) {
  // local state
  const [viewType, setViewType] = React.useState("Table");

  const { pluginsState: organizationPluginsState } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pluginsState: state.pluginsState,
      }),
      []
    )
  );

  // API/ store
  const [loading, error, dataListInitial, refetch] =
    usePluginConfigurationStore(stateSelector);

  const dataList = dataListInitial.map((data) => {
    const newData = data;
    newData.orgPluginDisabled =
      organizationPluginsState[data.name] !== undefined &&
      organizationPluginsState[data.name].disabled;
    newData.plugin_type = type;
    newData.refetch = refetch;
    return newData;
  });

  // page title
  useTitle(`IntelOwl | ${heading}`, { restoreOnUnmount: true });

  return (
    <Container fluid>
      {/* Heading */}
      <Row className="d-flex-start-center mb-2">
        <Col className="ps-0">
          <h1>
            {heading}&nbsp;
            <small className="text-muted">{dataList?.length} total</small>
          </h1>
          <span className="text-muted">{description}</span>
        </Col>
      </Row>
      {/* Actions */}
      <Row className="bg-dark d-flex-between-center">
        <Col>
          <TableHintIcon />
        </Col>
        <Col>
          <span className="text-muted">
            Note: Hover over a configured icon to view configuration status and
            errors if any.
          </span>
        </Col>
        <Col className="pt-1 d-flex align-items-start justify-content-end">
          <ButtonSelect
            choices={["Table", "Cards"]}
            value={viewType}
            onChange={setViewType}
            className="bg-tertiary"
            buttonProps={{
              size: "sm",
              className: "text-light",
            }}
          />
          <SyncButton onClick={refetch} className="ms-2" />
        </Col>
      </Row>
      {/* Table/Card View */}
      <Row>
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <DataTable
              data={dataList}
              config={tableConfig}
              initialState={tableInitialState}
              columns={columns}
              TableBodyComponent={
                viewType === "Cards" ? TableBodyComponent : undefined
              }
            />
          )}
        />
      </Row>
    </Container>
  );
}

TableBodyComponent.propTypes = {
  page: PropTypes.array.isRequired,
};

PluginWrapper.propTypes = {
  heading: PropTypes.string.isRequired,
  description: PropTypes.string.isRequired,
  stateSelector: PropTypes.func.isRequired,
  columns: PropTypes.array.isRequired,
  type: PropTypes.number.isRequired,
};
