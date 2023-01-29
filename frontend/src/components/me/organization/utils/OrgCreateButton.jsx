import React from "react";
import PropTypes from "prop-types";
import { Col, FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, Formik } from "formik";
import { IoMdPersonAdd } from "react-icons/io";

import { PopupFormButton } from "@certego/certego-ui";

import { createOrganization } from "../api";

// constants
const initialValues = {
  name: "",
};

// methods
const onValidate = (values) => {
  const minLength = 4;
  const maxLength = 32;
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

// Organization Create Form
function OrganizationCreateForm({ onFormSubmit }) {
  console.debug("OrganizationCreateForm rendered!");

  const onSubmit = React.useCallback(
    async (values, formik) => {
      try {
        await createOrganization(values);
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
            <Label className="required" for="orgforminput-name" md={3}>
              Organization Name
            </Label>
            <Col md={6}>
              <Input
                autoFocus
                id="orgforminput-name"
                type="text"
                name="name"
                bsSize="sm"
                onChange={formik.handleChange}
              />
            </Col>
            <Col md={2}>
              <Button
                type="submit"
                id="orgforminput-submit"
                disabled={!(formik.isValid || formik.isSubmitting)}
                color="darker"
                size="sm"
                md={2}
              >
                {formik.isSubmitting && <Spinner size="sm" />}Create
              </Button>
            </Col>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

function OrgCreateIcon() {
  return (
    <span>
      <IoMdPersonAdd className="me-1" /> Create a new organization
    </span>
  );
}

// Popover Button for organization create form
function OrgCreateButton({ onCreate }) {
  return (
    <PopupFormButton
      id="orgcreateform-icon"
      popOverPlacement="bottom"
      Icon={OrgCreateIcon}
      Form={OrganizationCreateForm}
      onFormSuccess={onCreate}
      size="md"
    />
  );
}

OrganizationCreateForm.propTypes = {
  onFormSubmit: PropTypes.func.isRequired,
};

OrgCreateButton.propTypes = {
  onCreate: PropTypes.func.isRequired,
};

export default OrgCreateButton;
