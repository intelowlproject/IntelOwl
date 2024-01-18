import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Alert } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import { useNavigate } from "react-router-dom";
import { INTELOWL_DOCS_URL } from "../../../constants/environment";

export function InviteOnlyAlert() {
  return (
    <Alert
      color="accent-2"
      id="inviteonly-info"
      className="col-12 px-1 text-center"
    >
      <h5 className="text-info">
        <MdInfoOutline size="1.15rem" />
        &nbsp;Sign up below to join the waitlist!
      </h5>
      <p>
        Please note that IntelOwl is operated as an invite-only trust group.
        Once you sign up, our team will reach out to you at the provided email
        address.
        <br />
        <span className="font-italic text-accent">
          We recommend signing up with a business email address and not a
          personal one to increase your chances of getting access.
        </span>
      </p>
    </Alert>
  );
}

export function AfterRegistrationModalAlert(props) {
  // modal state from props
  const { isOpen, setIsOpen } = props;
  const navigate = useNavigate();

  // callbacks
  const toggle = React.useCallback(() => {
    navigate("/");
    setIsOpen((open) => !open);
  }, [navigate, setIsOpen]);

  return (
    <Modal
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      isOpen={isOpen}
      keyboard={false}
      backdrop="static"
      labelledBy="Registration successful modal"
    >
      <ModalHeader toggle={toggle}>Registration successful! 🥳</ModalHeader>
      <ModalBody className="px-5">
        <>
          <section>
            <Alert color="success" className="text-center">
              <h3>Thank you for signing up on IntelOwl! 🤝</h3>
            </Alert>
          </section>
          <section className="mt-4">
            <strong className="h6">
              <u>Next Steps:</u>
            </strong>
            <ol className="mt-2">
              <li>
                Verify your email address. We have already sent you a{" "}
                <abbr title="Didn't receive ? No worries, request again.">
                  link
                </abbr>
                .
              </li>
              <li>Our team will reach out to you soon afterwards.</li>
            </ol>
          </section>
        </>
      </ModalBody>
    </Modal>
  );
}

export function ConfigurationModalAlert(props) {
  const { isOpen, setIsOpen, title } = props;
  const navigate = useNavigate();

  // callbacks
  const toggle = React.useCallback(() => {
    navigate("/");
    setIsOpen((open) => !open);
  }, [navigate, setIsOpen]);

  return (
    <Modal
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      isOpen={isOpen}
      keyboard={false}
      backdrop="static"
      labelledBy="Configuration modal"
    >
      <ModalHeader toggle={toggle}>Warning</ModalHeader>
      <ModalBody className="px-5">
        <>
          <section>
            <Alert color="warning" className="text-center">
              <h3>{title}</h3>
            </Alert>
          </section>
          <section className="mt-4">
            <p>
              If you are an admin please check the{" "}
              <a href={INTELOWL_DOCS_URL} target="_blank" rel="noreferrer">
                documentation
              </a>{" "}
              and correctly configure all the required variables.
            </p>
          </section>
        </>
      </ModalBody>
    </Modal>
  );
}

AfterRegistrationModalAlert.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  setIsOpen: PropTypes.func.isRequired,
};

ConfigurationModalAlert.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  setIsOpen: PropTypes.func.isRequired,
  title: PropTypes.string.isRequired,
};
