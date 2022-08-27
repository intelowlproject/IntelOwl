import React from "react";
import { Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import Config from "./Config";

export default function UserConfig() {
  console.debug("Config rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Your custom configuration</h4>
      <Config
        configFilter={(resp) => resp.filter((item) => !item.organization)}
      />
    </Container>
  );
}
