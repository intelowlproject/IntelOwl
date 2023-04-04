import React from "react";
import { Col, FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, Formik } from "formik";
import { IoMdSave } from "react-icons/io";
import PropTypes from "prop-types";

import { addToast, PopupFormButton } from "@certego/certego-ui";

import { saveJobAsPlaybook } from "../api";

// constants
const initialValues = {
  name: "",
  description: "",
  jobId: "",
};

// methods
const onValidate = (values) => {
  const minLength = 3;
  const errors = {};
  if (!values.name) {
    errors.name = "This field is required.";
  } else if (values.name.length < minLength) {
    errors.name = `This field must be at least ${minLength} characters long`;
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
        addToast(<span>Error!</span>, e.parsedMsg, "warning");
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
                  Playbook name
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
                  Playbook description
                </Label>
                <textarea
                  id="forminput-description"
                  type="text"
                  name="description"
                  style={{ width: "-webkit-fill-available" }}
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
      <IoMdSave className="me-2" /> Save As Playbook
    </span>
  );
}

export function SaveAsPlaybookButton({ jobId }) {
  initialValues.jobId = jobId;
  return (
    <PopupFormButton
      id="saveasplaybook"
      className="me-2"
      Form={SaveAsPlaybookForm}
      Icon={SaveAsPlaybookIcon}
      popOverPlacement="bottom"
    />
  );
}

SaveAsPlaybookForm.propTypes = {
  onFormSubmit: PropTypes.func.isRequired,
};

SaveAsPlaybookButton.propTypes = {
  jobId: PropTypes.number.isRequired,
};

export default SaveAsPlaybookButton;
