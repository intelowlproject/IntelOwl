import React from "react";
import { Nav, NavItem, NavLink, TabContent, TabPane } from "reactstrap";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";
import { FaUserSecret } from "react-icons/fa";

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

  [configs?.user_config, configs?.organization_config].forEach((config) => {
    config?.sort((itemA, itemB) => {
      // sort by required
      if (!itemA.required && itemB.required) {
        return 1;
      }
      if (itemA.required && !itemB.required) {
        return -1;
      }
      // sort by attribute name (not required fields)
      if (!itemA.required && !itemB.required) {
        const attributeA = itemA.attribute.toUpperCase(); // ignore upper and lowercase
        const attributeB = itemB.attribute.toUpperCase(); // ignore upper and lowercase
        if (attributeA < attributeB) {
          return -1;
        }
        if (attributeA > attributeB) {
          return 1;
        }
      }
      return 0;
    });
  });

  const isUserOwnerOrAdmin = isUserOwner || isUserAdmin(user.username);

  return (
    <div id="plugin-config-container">
      {/* plugin config */}
      <Nav tabs className="mt-2">
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
                Note: User configuration overrides the organization&apos;s
                configuration (if any).
              </small>
              <small className="d-flex align-items-center mt-2">
                <span className="text-danger ms-3 me-2">*</span>
                <strong className="text-muted">Required field</strong>
              </small>
              <small className="d-flex align-items-center">
                <FaUserSecret className="mx-2" />
                <span className="text-muted">
                  <strong>Secret field:&nbsp;</strong>
                  <span className="text-muted flex-wrap">
                    Only org admins can view the org&apos;s secrets. Other users
                    will see the placeholder ********* and will be able to
                    change its value by setting their user secret.
                  </span>
                </span>
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
              <small className="d-flex align-items-center mt-2">
                <span className="text-danger ms-3 me-2">*</span>
                <strong className="text-muted">Required field</strong>
              </small>
              <small className="d-flex align-items-center">
                <FaUserSecret className="mx-2" />
                <span className="text-muted">
                  <strong>Secret field:&nbsp;</strong>
                  <span className="text-muted flex-wrap">
                    Only org admins can view the org&apos;s secrets. Other users
                    will see the placeholder ********* and will be able to
                    change its value by setting their user secret.
                  </span>
                </span>
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
