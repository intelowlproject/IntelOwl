import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { ContentSection, CustomJsonInput } from "@certego/certego-ui";

import usePluginConfigurationStore from "../../../stores/usePluginConfigurationStore";
import markdownToHtml from "../../common/markdownToHtml";

// constants
const stateSelector = (state) => [state.analyzersJSON, state.connectors.JSON];

// components
export default function RuntimeConfigurationModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;

  const [jsonInput, setJsonInput] = React.useState({});

  const [analyzersJSON, connectorsJSON] =
    usePluginConfigurationStore(stateSelector);

  const combinedParamsMap = React.useMemo(
    () => ({
      ...formik.values.analyzers.reduce(
        (acc, { value: name }) => ({
          ...acc,
          [name]: analyzersJSON?.[name].params,
        }),
        {}
      ),
      ...formik.values.connectors.reduce(
        (acc, { value: name }) => ({
          ...acc,
          [name]: connectorsJSON?.[name].params,
        }),
        {}
      ),
    }),
    [
      formik.values.analyzers,
      formik.values.connectors,
      analyzersJSON,
      connectorsJSON,
    ]
  );

  const defaultNameParamsMap = React.useMemo(
    () =>
      Object.entries(combinedParamsMap).reduce(
        (acc, [name, params]) => ({
          ...acc,
          [name]: Object.entries(params).reduce(
            (acc2, [pName, { value }]) => ({
              ...acc2,
              [pName]: value,
            }),
            {}
          ),
        }),
        {}
      ),
    [combinedParamsMap]
  );

  const placeholder = React.useMemo(
    () => ({
      ...defaultNameParamsMap,
      ...formik.values.runtime_configuration, // previous values if any
    }),
    [defaultNameParamsMap, formik.values.runtime_configuration]
  );

  const saveAndCloseModal = () => {
    // we only want to save configuration against plugins whose params dict is not empty or was modified
    if (jsonInput?.jsObject) {
      const runtimeCfg = Object.entries(jsonInput.jsObject).reduce(
        (acc, [name, params]) =>
          Object.keys(params).length > 0 &&
          JSON.stringify(defaultNameParamsMap[name]) !== JSON.stringify(params)
            ? { ...acc, [name]: params }
            : acc,
        {}
      );
      formik.setFieldValue("runtime_configuration", runtimeCfg, false);
    }
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
      labelledBy="Edit Runtime Configuration"
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Edit Runtime Configuration
      </ModalHeader>
      <ModalBody className="d-flex-start-start bg-body">
        <ContentSection className="bg-darker">
          <small className="text-muted">
            Note: Edit this only if you know what you are doing!
          </small>
          <CustomJsonInput
            id="edit_runtime_configuration-modal"
            placeholder={placeholder}
            onChange={setJsonInput}
            height="500px"
            width="450px"
          />
          <div className="mt-2 d-flex align-items-center justify-content-end">
            <Button
              onClick={toggle}
              size="sm"
              color=""
              className="btn-link text-gray"
            >
              Ignore changes & close
            </Button>
            <Button
              disabled={jsonInput?.error}
              onClick={saveAndCloseModal}
              size="sm"
              color="info"
              className="ms-2"
            >
              Save & Close
            </Button>
          </div>
        </ContentSection>
        <ContentSection className="ms-2 bg-darker">
          {Object.entries(combinedParamsMap).map(([name, params]) => (
            <div key={`editruntimeconf__${name}`}>
              <h6 className="text-secondary">{name}</h6>
              {Object.entries(params).length ? (
                <ul>
                  {Object.entries(params).map(([pName, pObj]) => (
                    <li key={`editruntimeconf__${name}__${pName}`}>
                      <span className="text-pre">{pName}</span>
                      &nbsp;
                      <em className="text-muted">({pObj.type})</em>
                      <dd className="text-muted">
                        {markdownToHtml(pObj.description)}
                      </dd>
                    </li>
                  ))}
                </ul>
              ) : (
                <span className="text-muted fst-italic">null</span>
              )}
            </div>
          ))}
        </ContentSection>
      </ModalBody>
    </Modal>
  );
}

RuntimeConfigurationModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
