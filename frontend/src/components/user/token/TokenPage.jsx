import React from "react";
import { Alert, Container, Row } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";

import TokenAccess from "./TokenAccess";
import { PYINTELOWL_GH_URL } from "../../../constants/environment";

export default function TokenPage() {
  console.debug("APIPage rendered!");

  // page title
  useTitle("IntelOwl | API", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      {/* Alert */}
      <Row className="my-4">
        <Alert color="secondary" className="mx-3 mx-md-auto text-center">
          <span>
            You can generate an API key to access IntelOwl&apos;s RESTful API.
            Take a look to the available Python and Go clients:
            <a
              href={PYINTELOWL_GH_URL}
              target="_blank"
              rel="noreferrer"
              className="link-primary"
            >
              Learn more
            </a>
            .
          </span>
        </Alert>
      </Row>
      {/* API Access */}
      <h6>API Access</h6>
      <ContentSection className="bg-body border border-dark">
        <TokenAccess />
      </ContentSection>
    </Container>
  );
}
