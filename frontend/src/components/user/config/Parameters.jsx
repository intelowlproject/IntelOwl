import React from "react";
import PropTypes from "prop-types";
import useTitle from "react-use/lib/useTitle";
import { Container } from "reactstrap";
import Config from "./Config";
import { PluginConfigTypesNumeric } from "../../../constants/pluginConst";

export default function Parameters({
  additionalConfigData,
  filterFunction,
  editable,
}) {
  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <Config
        configFilter={(resp) =>
          resp.filter(
            (item) =>
              filterFunction(item) &&
              item.config_type === PluginConfigTypesNumeric.PARAMETER,
          )
        }
        additionalConfigData={{
          ...additionalConfigData,
          config_type: PluginConfigTypesNumeric.PARAMETER,
        }}
        dataName="params"
        editable={editable}
      />
    </Container>
  );
}

Parameters.propTypes = {
  additionalConfigData: PropTypes.object,
  filterFunction: PropTypes.func,
  editable: PropTypes.bool.isRequired,
};

Parameters.defaultProps = {
  additionalConfigData: {},
  filterFunction: () => true,
};
