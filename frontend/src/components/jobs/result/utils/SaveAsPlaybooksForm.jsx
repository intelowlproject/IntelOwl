import React from "react";
import PropTypes from "prop-types";
import { Col, FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, Formik } from "formik";
import { IoMdPersonAdd } from "react-icons/io";

import { PopupFormButton } from "@certego/certego-ui";

import { saveJobAsPlaybook } from "../api";

// constants
const initialValues = {
  name: "",
  description: "",
};

// methods
const onValidate = (values) => {
  const minLength = 3;
  const maxLength = 16;
  const errors = {};
  if (!values.name) {
    errors.name = "This field is required.";
  } else if (values.name.length < minLength) {
    errors.name = `This field must be at least ${minLength} characters long`;
  } else if (values.username.length >= maxLength) {
    errors.name = `This field must be no more than ${maxLength} characters long.`;
  }
  return errors;
};

// Invitation Form
export function SaveAsPlaybookForm({ onFormSubmit }) {
  console.debug("InvitationForm rendered!");

  const onSubmit = React.useCallback(
    async (values, formik) => {
      try {
        await saveJobAsPlaybook(values);
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
      validateOnChange
    >
      {(formik) => (
        <Form className="mx-2 my-3">
          <FormGroup row className="d-flex flex-wrap">
            <Label className="required" for="forminput-username" md={4}>
              User&apos;s username
            </Label>
            <Col md={5}>
              <Input
                autoFocus
                id="forminput-username"
                type="text"
                name="username"
                onChange={formik.handleChange}
              />
            </Col>
            <Col md={2}>
              <Button
                type="submit"
                id="forminput-submit"
                disabled={!(formik.isValid || formik.isSubmitting)}
                color="darker"
                size="sm"
                md={2}
              >
                {formik.isSubmitting && <Spinner size="sm" />}Send
              </Button>
            </Col>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

// Popover Button for invitation form
function SaveAsPlaybookButton({ onCreate }) {
  return (
        <>
            <PopupFormButton
            id="saveasplaybook"
            title="Save Scan As Playbook"
            Form={SaveAsPlaybookForm}
            className="me-2"
            // onFormSuccess={onCreate}
            popOverPlacement="bottom"
            outline
            color="info" />
                <MdSave />
                    &nbsp;Save Scan As Playbook
            <PopupFormButton />
        </>
  );
}

export default SaveAsPlaybookButton;
