import React from "react";
import { Col, FormGroup, Label, Button, Spinner, Input } from "reactstrap";
import { Form, Formik } from "formik";
import { IoMdSave } from "react-icons/io";
import PropTypes from "prop-types";

import { addToast, PopupFormButton } from "@certego/certego-ui";

import { saveJobAsPlaybook } from "./jobBarApi";

// constants
const initialValues = {
  name: "",
  description: "",
  analyzers: [],
  connectors: [],
  pivots: [],
  runtimeConfiguration: {},
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
  if (!values.description) {
    errors.description = "This field is required.";
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
      } catch (error) {
        addToast(<span>Error!</span>, error.parsedMsg, "warning");
      } finally {
        formik.setSubmitting(false);
      }
    },
    [onFormSubmit],
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
                <Label className="required" for="forminput-name" md={12}>
                  Playbook name
                </Label>
                <Input
                  autoFocus
                  id="forminput-name"
                  type="text"
                  name="name"
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                />
                {formik.touched.name && (
                  <small className="text-danger">{formik.errors.name}</small>
                )}
              </div>

              <div className="p-3">
                <Label className="required" for="forminput-description" md={12}>
                  Playbook description
                </Label>
                <textarea
                  id="forminput-description"
                  type="text"
                  name="description"
                  style={{ width: "-webkit-fill-available" }}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                />
                {formik.touched.description && (
                  <small className="text-danger">
                    {formik.errors.description}
                  </small>
                )}
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
    <span className="d-flex align-items-center">
      <IoMdSave className="me-1" />
      Save As Playbook
    </span>
  );
}

export function SaveAsPlaybookButton({ job }) {
  initialValues.analyzers = job.analyzers_to_execute;
  initialValues.connectors = job.connectors_to_execute;
  initialValues.pivots = job.pivots_to_execute;
  initialValues.runtimeConfiguration = job.runtime_configuration;
  if (job.tags.length) {
    initialValues.tags_labels = [];
    job.tags.forEach((tag) => initialValues.tags_labels.push(tag.label));
  }
  initialValues.tlp = job.tlp;
  initialValues.scan_mode = job.scan_mode;
  initialValues.scan_check_time = job.scan_check_time;
  return (
    <PopupFormButton
      id="saveasplaybook"
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
  job: PropTypes.object.isRequired,
};

export default SaveAsPlaybookButton;
