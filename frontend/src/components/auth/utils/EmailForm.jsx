import React from "react";
import PropTypes from "prop-types";
import { FormGroup, Label, Input, Button, Spinner } from "reactstrap";
import { Form, Formik } from "formik";

import ReCAPTCHAInput from "./ReCAPTCHAInput";
import { RECAPTCHA_SITEKEY } from "../../../constants/environment";
import { RecaptchaValidator, EmailValidator } from "./validator";

// constants
const initialValues = {
  email: "",
  recaptcha: "noKey",
};

// methods
const onValidate = (values) => {
  const errors = {};
  // email
  const emailErrors = EmailValidator(values.email);
  if (emailErrors.email) {
    errors.email = emailErrors.email;
  }
  // recaptcha
  const recaptchaErrors = RecaptchaValidator(values.recaptcha);
  if (recaptchaErrors.recaptcha) {
    errors.recaptcha = recaptchaErrors.recaptcha;
  }
  return errors;
};

// Resend Verification Email Form
export default function EmailForm({ onFormSubmit, apiCallback, ...restProps }) {
  // callbacks
  const onSubmit = React.useCallback(
    async (values) => {
      try {
        await apiCallback(values);
        onFormSubmit();
      } catch (e) {
        // error will be handled by apiCallback
      }
    },
    [apiCallback, onFormSubmit]
  );

  return (
    <Formik
      initialValues={initialValues}
      validate={onValidate}
      onSubmit={onSubmit}
      validateOnMount
    >
      {(formik) => (
        <Form {...restProps}>
          {/* Email field */}
          <FormGroup>
            <Label className="required" htmlFor="EmailForm__email">
              Email Address
            </Label>
            <Input
              id="EmailForm__email"
              autoFocus
              type="text"
              name="email"
              className="form-control form-control-sm"
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              valid={!formik.errors.email}
              invalid={formik.errors.email && formik.touched.email}
            />
            {formik.touched.email && <small>{formik.errors.email}</small>}
          </FormGroup>
          {/* reCAPTCHA */}
          <FormGroup row>
            {RECAPTCHA_SITEKEY && (
              <ReCAPTCHAInput
                id="RegisterForm__recaptcha"
                className="m-3 mx-auto"
              />
            )}
          </FormGroup>
          {/* Submit */}
          <FormGroup className="">
            <Button
              type="submit"
              disabled={!(formik.isValid || formik.isSubmitting)}
              color="darker"
              className="mx-auto"
            >
              {formik.isSubmitting && <Spinner size="sm" />} Send
            </Button>
          </FormGroup>
        </Form>
      )}
    </Formik>
  );
}

EmailForm.propTypes = {
  onFormSubmit: PropTypes.func.isRequired,
  apiCallback: PropTypes.func.isRequired,
};
