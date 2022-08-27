import React from "react";
import { Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import ConfigContainer from "./ConfigContainer";

export default function UserConfig() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <ConfigContainer filterFunction={(item) => !item.organization} />
    </Container>
  );
}
