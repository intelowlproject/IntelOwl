import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button, Input } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";
import { sanitizeObservable } from "./utils";
import {
  DOMAIN_REGEX,
  IP_REGEX,
  HASH_REGEX,
  URL_REGEX,
} from "../../../constants/regexConst";

// components
export function MultipleObservablesModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;
  const [extractedObservables, setExtractedObservables] = React.useState({
    domain: [],
    ip: [],
    url: [],
    hash: [],
  });
  console.debug("MultipleObservablesModal - extractedObservables:");
  console.debug(extractedObservables);

  const observableType2RegExMap = {
    domain: DOMAIN_REGEX,
    ip: IP_REGEX,
    url: URL_REGEX,
    hash: HASH_REGEX,
  };

  const extractObservables = (inputText) => {
    const sanitizedText = sanitizeObservable(inputText);
    console.debug(sanitizedText);
    const observables = {
      domain: [],
      ip: [],
      url: [],
      hash: [],
    };
    Object.entries(observableType2RegExMap).forEach(([typeName, typeRegEx]) => {
      const match = sanitizedText.match(typeRegEx);
      console.debug(match);
      if (match) {
        observables[typeName] = match;
      }
    });
    console.debug(observables);
    setExtractedObservables(observables);
  };

  const saveAndCloseModal = () => {
    const observableNames = Object.values(extractedObservables).flat();
    formik.setFieldValue("observable_names", observableNames, false);
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="xl"
      isOpen={isOpen}
      toggle={toggle}
      keyboard={false}
      scrollable
      backdrop="static"
      labelledBy="Load Multiple Observables"
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Load Multiple Observables
      </ModalHeader>
      <ModalBody
        className="d-flex-column bg-body"
        id="load_multiple_observables-ModalBody"
      >
        <div className="d-flex-start-start bg-body">
          <ContentSection
            className="bg-darker"
            id="load_multiple_observables-section"
            style={{ width: "50%", maxHeight: "560px" }}
          >
            <small className="text-muted">
              Any text can be pasted and the observables will be extracted for
              further lookup.
            </small>
            <Input
              id="load_multiple_observables-textArea"
              name="textArea"
              type="textarea"
              onChange={(e) => extractObservables(e.target.value)}
              style={{ minHeight: "500px", overflowY: "auto" }}
              className="my-2"
            />
          </ContentSection>
          {/* lateral menu with the extracted observables */}
          <ContentSection
            className="ms-2 bg-darker"
            style={{ width: "50%", maxHeight: "560px", overflowY: "auto" }}
          >
            <div style={{ minHeight: "540px", overflowY: "auto" }}>
              <h5 className="text-accent">Extracted observables</h5>
              {Object.values(extractedObservables).flat().length === 0 ? (
                <small className="text-muted">No observable found.</small>
              ) : (
                Object.entries(extractedObservables).map(([key, iocs]) => (
                  <div>
                    <h6 key={key} className="text-secondary px-3">
                      {key}:
                    </h6>
                    <ul>
                      {iocs?.map((ioc) => (
                        <li key={`extractedObservables__${key}__${ioc}`}>
                          {ioc}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))
              )}
            </div>
          </ContentSection>
        </div>
        <div className="d-flex justify-content-end mb-1">
          <Button
            disabled={Object.values(extractedObservables).flat().length === 0}
            onClick={saveAndCloseModal}
          >
            Extract
          </Button>
        </div>
      </ModalBody>
    </Modal>
  );
}

MultipleObservablesModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
