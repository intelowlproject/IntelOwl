import React from "react";
import { Row, Col, Container } from "reactstrap";
import { FaTwitter, FaGithub, FaGoogle } from "react-icons/fa";

import { Toaster, ScrollToTopButton, useToastr } from "@certego/certego-ui";

import { VERSION, INTELOWL_TWITTER_ACCOUNT } from "../constants/environment";

// constants
const selector = (state) => state.toasts;

function AppFooter() {
  console.debug("AppFooter rendered!");

  // consume store
  const toasts = useToastr(selector);

  return (
    <footer className="flex-no-shrink">
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
            md={12}
            lg={8}
            className="g-0 d-flex-center flex-column flex-lg-row text-center lead"
          >
            <Col className="text-muted small">{VERSION}</Col>
          </Row>
          <Row
            md={12}
            className="g-0 mt-3 d-flex-center flex-column flex-lg-row text-center"
          >
            <Col>
              <a
                href={`https://twitter.com/${INTELOWL_TWITTER_ACCOUNT}`}
                target="_blank"
                rel="noopener noreferrer"
                className="ms-md-2 twitter-follow-button"
              >
                <FaTwitter /> Follow @{INTELOWL_TWITTER_ACCOUNT}
              </a>
            </Col>
            <Col>
              <a
                href="https://www.honeynet.org/gsoc/"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FaGoogle /> Honeynet on GSOC
              </a>
            </Col>
            <Col>
              <a
                href="https://github.com/intelowlproject"
                target="_blank"
                rel="noopener noreferrer"
                className="ms-md-2 github-button"
              >
                {" "}
                <FaGithub /> Connect on Github{" "}
              </a>
            </Col>
          </Row>
        </Container>
        {/* Scroll to top button */}
        <ScrollToTopButton />
      </div>
    </footer>
  );
}

export default AppFooter;
