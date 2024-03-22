import React from "react";
import PropTypes from "prop-types";
import { Container, Col } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { Link } from "react-router-dom";

import {
  Loader,
  ContentSection,
  DataTable,
  TableHintIcon,
  SyncButton,
  ButtonSelect,
} from "@certego/certego-ui";

import { PluginInfoCard } from "./utils";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { PluginsTypes } from "../../../constants/pluginConst";

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
      [],
    ),
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
    <Container fluid className="px-0">
      {/* Heading */}
      <div className="d-flex-start-center mb-2">
        <Col className="ps-0">
          <h1>
            {heading}&nbsp;
            <small className="text-muted">{dataList?.length} total</small>
          </h1>
          <span className="text-muted">
            {description} Fore more info check the{" "}
            <Link
              to="https://intelowl.readthedocs.io/en/latest/Usage.html#plugins-framework"
              target="_blank"
            >
              official doc
            </Link>
          </span>
        </Col>
      </div>
      {/* Actions */}
      <div className="bg-dark d-flex-between-center">
        <div className="ps-3 d-flex">
          <TableHintIcon />
          <span className="ps-2 text-muted">
            Note: Hover over a configured icon to view configuration status and
            errors if any.
          </span>
        </div>
        <div className="pt-1 pe-3 d-flex align-items-start justify-content-end">
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
        </div>
      </div>
      {/* Table/Card View */}
      <div style={{ height: "70vh", overflow: "scroll" }}>
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
      </div>
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
  type: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
};
