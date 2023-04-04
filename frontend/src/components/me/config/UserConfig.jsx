import React from "react";
import { Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { Link } from "react-router-dom";
import ConfigContainer from "./ConfigContainer";

export default function UserConfig() {
  console.debug("UserConfigPage rendered!");

  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      <h4>Your plugin configuration</h4>
      <span className="text-muted">
        Note: Your plugin configuration overrides your{" "}
        <Link to="/me/organization/config">
          organization&apos;s configuration
        </Link>{" "}
        (if any).
      </span>
      <ConfigContainer filterFunction={(item) => !item.organization} />
    </Container>
  );
}
