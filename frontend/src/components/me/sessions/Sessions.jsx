import React from "react";
import { Alert, Container, Row } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";

import SessionsList from "./SessionsList";
import APIAccess from "./APIAccess";
import { INTELOWL_DOCS_URL } from "../../../constants/environment";

export default function Sessions() {
  console.debug("Sessions rendered!");

  // page title
  useTitle("IntelOwl | Sessions", {
    restoreOnUnmount: true,
  });

  return (
    <Container>
      {/* Alert */}
      <Row className="my-4">
        <Alert color="secondary" className="mx-3 mx-md-auto text-center">
          <span>
            You can generate an API key to access IntelOwl's RESTful API.&nbsp;
            <a
              href={`${INTELOWL_DOCS_URL}Usage.html#client`}
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
        <APIAccess />
      </ContentSection>
      {/* Sessions List */}
      <h6>Browser Sessions</h6>
      <ContentSection className="bg-body border border-dark">
        <SessionsList />
      </ContentSection>
    </Container>
  );
}
