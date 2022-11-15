import React from "react";
import { Col, FormGroup, Label, Button, Spinner, Input, Row } from "reactstrap";
import { Form, Formik } from "formik";
import { IoMdPersonAdd } from "react-icons/io";
import PropTypes from "prop-types";

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
  } else if (values.name.length >= maxLength) {
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
            <Col>
              <div className="p-3">
                <Label className="required" for="forminput-username" md={12}>
                  Playbok name
                </Label>
                  <Input
                    autoFocus
                    id="forminput-name"
                    type="text"
                    name="name"
                    onChange={formik.handleChange}
                  />
              </div>

              <div className="p-3">
                <Label className="required" for="forminput-name" md={12}>
                  Playbok description
                </Label>
                  <Input
                    autoFocus
                    id="forminput-description"
                    type="text"
                    name="description"
                    onChange={formik.handleChange}
                  />
              </div>
              <div className="p-3 d-flex justify-content-center">
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
              </div>
            </Col>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

function SaveAsPlaybookIcon() {
  return (
    <span>
      <IoMdPersonAdd className="me-2" /> Save As Playbook
    </span>
  );
}

export function SaveAsPlaybookButton({ onCreate }) {
  return (
            <PopupFormButton
                id="saveasplaybook"
                className="me-2"
                Form={SaveAsPlaybookForm}
                onFormSuccess={onCreate}
                Icon={SaveAsPlaybookIcon}
                popOverPlacement="bottom"
              />
  );
}

SaveAsPlaybookForm.propTypes = {
  onFormSubmit: PropTypes.func.isRequired,
}

SaveAsPlaybookForm.propTypes = {
  onCreate: PropTypes.func.isRequired,
}

export default SaveAsPlaybookButton;
