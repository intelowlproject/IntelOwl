import React from "react";
import { Row, Col, Container } from "reactstrap";
import { FaTwitter } from "react-icons/fa";

import { Toaster, ScrollToTopButton, useToastr } from "@certego/certego-ui";

import {
  VERSION,
  INTELOWL_TWITTER_ACCOUNT
} from "../constants/environment";

// constants
const selector = (state) => state.toasts;

function AppFooter() {
  console.debug("AppFooter rendered!");

  // consume store
  const toasts = useToastr(selector);

  return (
    <div className="d-flex flex-column">
      {/* Toasts */}
      <section className="fixed-bottom" id="app-toasts">
        {toasts.map((tProps) => (
          <Toaster key={tProps.id} {...tProps} />
        ))}
      </section>
      {/* Footer */}
      <Container fluid className="border-top mt-2 py-1">
        <Row
          noGutters
          md={12}
          lg={8}
          className="d-flex-center flex-column flex-lg-row text-center lead"
        >
          <Col className="text-muted small">
            {VERSION}
          </Col>
        </Row>
        <Row
          noGutters
          md={12}
          className="mt-3 d-flex-center flex-column flex-lg-row text-center"
        >
          <Col>
            <a
              href={`https://twitter.com/${INTELOWL_TWITTER_ACCOUNT}`}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-md-2 twitter-follow-button"
            >
              <FaTwitter /> Follow @{INTELOWL_TWITTER_ACCOUNT}
            </a>
          </Col>
        </Row>
      </Container>
      {/* Scroll to top button */}
      <ScrollToTopButton />
    </div>
  );
}

export default AppFooter;
