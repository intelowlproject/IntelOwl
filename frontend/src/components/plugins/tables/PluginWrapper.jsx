import React from "react";
import PropTypes from "prop-types";
import { Container, Col } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { Link } from "react-router-dom";

import {
  Loader,
  DataTable,
  TableHintIcon,
  SyncButton,
} from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { PluginsTypes } from "../../../constants/pluginConst";
import { INTELOWL_DOCS_URL } from "../../../constants/environment";

// table config
const tableConfig = {};
const tableInitialState = {
  pageSize: 6,
  sortBy: [{ id: "name", desc: false }],
};

export default function PluginWrapper({
  heading,
  description,
  stateSelector,
  columns,
  type,
}) {
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
            {description} For more info check the{" "}
            <Link
              to={`${INTELOWL_DOCS_URL}IntelOwl/usage/#plugins-framework`}
              target="_blank"
            >
              official doc.
            </Link>
          </span>
        </Col>
      </div>
      {/* Actions */}
      <div className="px-3 bg-dark d-flex justify-content-end align-items-center">
        <TableHintIcon />
        <SyncButton onClick={refetch} className="ms-auto m-0 py-1" />
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
            />
          )}
        />
      </div>
    </Container>
  );
}

PluginWrapper.propTypes = {
  heading: PropTypes.string.isRequired,
  description: PropTypes.string.isRequired,
  stateSelector: PropTypes.func.isRequired,
  columns: PropTypes.array.isRequired,
  type: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
};
