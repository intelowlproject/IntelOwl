import React from "react";
import PropTypes from "prop-types";
import { Col, FormGroup, Label } from "reactstrap";
import { Submit, CustomInput as FormInput } from "formstrap";
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
function OrganizationCreateForm({ onFormSubmit, }) {
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
      validateOnMount
    >
      {(formik) => (
        <Form className="mx-2 my-3">
          <FormGroup row className="d-flex flex-wrap">
            <Col md={3}>
              <Label className="required" htmlFor="name">
                Organization Name
              </Label>
            </Col>
            <Col md={6}>
              <FormInput
                autoFocus
                id="orgforminput-name"
                type="text"
                name="name"
                className="form-control form-control-sm"
              />
            </Col>
            <Col md={2}>
              <Submit
                id="orgforminput-submit"
                disabled={!(formik.isValid || formik.isSubmitting)}
                withSpinner
                color="darker"
                size="sm"
              >
                {!formik.isSubmitting && "Create"}
              </Submit>
            </Col>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

// Popover Button for organization create form
function OrgCreateButton({ onCreate, }) {
  return (
    <PopupFormButton
      id="orgcreateform-icon"
      popOverPlacement="bottom"
      Icon={() => (
        <span>
          <IoMdPersonAdd className="mr-1" /> Create a new organization
        </span>
      )}
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
