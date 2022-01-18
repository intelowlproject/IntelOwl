import React from "react";
import PropTypes from "prop-types";
import { Col, FormGroup, Label } from "reactstrap";
import { Submit, CustomInput as FormInput } from "formstrap";
import { Form, Formik } from "formik";
import { IoMdPersonAdd } from "react-icons/io";

import { PopupFormButton } from "@certego/certego-ui";

import { sendInvite } from "../api";

// constants
const initialValues = {
  username: "",
};

// methods
const onValidate = (values) => {
  const minLength = 3;
  const maxLength = 16;
  const errors = {};
  if (!values.username) {
    errors.username = "This field is required.";
  } else if (values.username.length < minLength) {
    errors.username = `This field must be at least ${minLength} characters long`;
  } else if (values.username.length >= maxLength) {
    errors.username = `This field must be no more than ${maxLength} characters long.`;
  }
  return errors;
};

// Invitation Form
function InvitationForm({ onFormSubmit, }) {
  console.debug("InvitationForm rendered!");

  const onSubmit = React.useCallback(
    async (values, formik) => {
      try {
        await sendInvite(values);
        onFormSubmit();
      } catch (e) {
        // error was handled inside sendInvite
      } finally {
        formik.setSubmitting(false);
      }
    },
    [onFormSubmit]
  );

  return (
    <Formik
      initialValues={initialValues}
      validate={onValidate}
      onSubmit={onSubmit}
      validateOnMount
    >
      {(formik) => (
        <Form className="mx-2 my-3">
          <FormGroup row className="d-flex flex-wrap">
            <Col md={4}>
              <Label className="required" htmlFor="username">
                User's username
              </Label>
            </Col>
            <Col md={5}>
              <FormInput
                autoFocus
                id="forminput-username"
                type="text"
                name="username"
                className="form-control form-control-sm"
              />
            </Col>
            <Col md={2}>
              <Submit
                id="forminput-submit"
                disabled={!(formik.isValid || formik.isSubmitting)}
                withSpinner
                color="darker"
                size="sm"
              >
                {!formik.isSubmitting && "Send"}
              </Submit>
            </Col>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

// Popover Button for invitation form
function InviteButton({ onCreate, }) {
  return (
    <PopupFormButton
      id="invitationform-icon"
      title="Invite User"
      titlePlacement="right-start"
      Icon={IoMdPersonAdd}
      Form={InvitationForm}
      onFormSuccess={onCreate}
      popOverPlacement="bottom"
      outline
      color="info"
      className="border border-tertiary"
    />
  );
}

InvitationForm.propTypes = {
  onFormSubmit: PropTypes.func.isRequired,
};

InviteButton.propTypes = {
  onCreate: PropTypes.func.isRequired,
};

export default InviteButton;
