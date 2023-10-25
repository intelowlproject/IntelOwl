import React from "react";
import PropTypes from "prop-types";
import useTitle from "react-use/lib/useTitle";
import { Container } from "reactstrap";
import Config from "./Config";
import { PluginConfigTypesNumeric } from "../../../constants/pluginConst";

export default function Secrets({
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
              item.config_type === PluginConfigTypesNumeric.SECRET,
          )
        }
        additionalConfigData={{
          ...additionalConfigData,
          config_type: PluginConfigTypesNumeric.SECRET,
        }}
        dataName="secrets"
        editable={editable}
      />
    </Container>
  );
}

Secrets.propTypes = {
  additionalConfigData: PropTypes.object,
  filterFunction: PropTypes.func,
  editable: PropTypes.bool.isRequired,
};

Secrets.defaultProps = {
  additionalConfigData: {},
  filterFunction: () => true,
};
