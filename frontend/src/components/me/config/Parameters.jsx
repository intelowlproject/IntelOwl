import React from "react";
import PropTypes from "prop-types";
import useTitle from "react-use/lib/useTitle";
import { Container } from "reactstrap";
import Config from "./Config";

export default function Parameters({ additionalConfigData, filterFunction }) {
  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <Config
        configFilter={(resp) =>
          resp.filter(
            (item) => filterFunction(item) && item.config_type === "1"
          )
        }
        additionalConfigData={{
          ...additionalConfigData,
          config_type: "1",
        }}
      />
    </Container>
  );
}

Parameters.propTypes = {
  additionalConfigData: PropTypes.object,
  filterFunction: PropTypes.func,
};

Parameters.defaultProps = {
  additionalConfigData: {},
  filterFunction: () => true,
};
