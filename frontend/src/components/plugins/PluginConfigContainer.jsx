import React from "react";
import { Nav, NavItem, NavLink, TabContent, TabPane } from "reactstrap";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";

import { Loader } from "@certego/certego-ui";

import { PluginConfigForm } from "./forms/PluginConfigForm";
import { API_BASE_URI } from "../../constants/apiURLs";
import { PluginConfigTypes } from "../../constants/pluginConst";
import { useOrganizationStore } from "../../stores/useOrganizationStore";
import { useAuthStore } from "../../stores/useAuthStore";

export function PluginConfigContainer({ pluginName, pluginType, toggle }) {
  console.debug("PluginConfigContainer rendered!");

  const [user] = useAuthStore((state) => [state.user]);
  const { isUserOwner, isUserAdmin, isInOrganization } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isUserOwner: state.isUserOwner,
        isUserAdmin: state.isUserAdmin,
        isInOrganization: state.isInOrganization,
      }),
      [],
    ),
  );

  const [activeTab, setActiveTab] = React.useState(
    PluginConfigTypes.USER_CONFIG,
  );

  // download plugin configs
  const [
    { data: configs, loading: loadingConfigs, error: errorConfigs },
    refetchPluginConfig,
  ] = useAxios(
    {
      url: `${API_BASE_URI}/${pluginType}/${pluginName}/plugin_config`,
    },
    { useCache: false },
  );

  const isUserOwnerOrAdmin = isUserOwner || isUserAdmin(user.username);

  return (
    <div id="plugin-config-container">
      {/* plugin config */}
      <Nav tabs className="mt-4">
        <NavItem>
          <NavLink
            className={
              activeTab === PluginConfigTypes.USER_CONFIG
                ? "active text-accent fw-bold"
                : ""
            }
            style={{ border: "1px solid #001d24" }}
            onClick={() => setActiveTab(PluginConfigTypes.USER_CONFIG)}
            id={`userconfig__${pluginName}`}
          >
            User config
          </NavLink>
        </NavItem>
        {isInOrganization && (
          <NavItem>
            <NavLink
              className={
                activeTab === PluginConfigTypes.ORG_CONFIG
                  ? "active text-accent fw-bold"
                  : ""
              }
              style={{ border: "1px solid #001d24" }}
              onClick={() => setActiveTab(PluginConfigTypes.ORG_CONFIG)}
              id={`orgconfig__${pluginName}`}
            >
              Org config
            </NavLink>
          </NavItem>
        )}
      </Nav>
      <Loader
        loading={loadingConfigs}
        error={errorConfigs}
        render={() => (
          <TabContent activeTab={activeTab} className="p-2 mt-2">
            <TabPane tabId={PluginConfigTypes.USER_CONFIG}>
              <small className="text-muted">
                Note: Your plugin configuration overrides your
                organization&apos;s configuration (if any).
              </small>
              <PluginConfigForm
                pluginName={pluginName}
                pluginType={pluginType}
                configType={PluginConfigTypes.USER_CONFIG}
                configs={configs.user_config}
                isUserOwnerOrAdmin={isUserOwnerOrAdmin}
                refetch={refetchPluginConfig}
                toggle={toggle}
              />
            </TabPane>
            <TabPane tabId={PluginConfigTypes.ORG_CONFIG}>
              <small className="text-muted">
                Note: Only org admins can modify the configuration,
                {isUserOwnerOrAdmin ? (
                  <span> other users can only view it</span>
                ) : (
                  <span className="text-accent"> you can only view it.</span>
                )}
              </small>
              <PluginConfigForm
                pluginName={pluginName}
                pluginType={pluginType}
                configType={PluginConfigTypes.ORG_CONFIG}
                configs={configs.organization_config}
                isUserOwnerOrAdmin={isUserOwnerOrAdmin}
                refetch={refetchPluginConfig}
                toggle={toggle}
              />
            </TabPane>
          </TabContent>
        )}
      />
    </div>
  );
}

PluginConfigContainer.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType: PropTypes.oneOf(["analyzer", "connector", "ingestor", "pivot"])
    .isRequired,
  toggle: PropTypes.func.isRequired,
};
