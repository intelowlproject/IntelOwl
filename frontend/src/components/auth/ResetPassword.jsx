import React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { FormGroup, Label, Col, Input, Button, Spinner } from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";

import { UUID_REGEX, PASSWORD_REGEX } from "../../constants/index";
import ReCAPTCHAInput from "./utils/ReCAPTCHAInput";
import { resetPassword } from "./api";
import { RECAPTCHA_SITEKEY } from "../../constants/environment";

// constants
const reMatcher = new RegExp(UUID_REGEX);
const initialValues = {
  password: "",
  confirmPassword: "",
  recaptcha: "noKey",
};
const onValidate = (values) => {
  const errors = {};

  // password fields
  if (!values.password) {
    errors.password = "Required";
  } else if (values.password.length < 12) {
    errors.password = "Must be 12 characters or more";
  } else if (!PASSWORD_REGEX.test(values.password)) {
    errors.password =
      "The password is entirely numeric or contains special characters";
  }
  if (!values.confirmPassword) {
    errors.confirmPassword = "Required";
  } else if (values.confirmPassword.length < 12) {
    errors.confirmPassword = "Must be 12 characters or more";
  }
  if (
    values.password.length > 0 &&
    values.confirmPassword.length > 0 &&
    values.password !== values.confirmPassword
  ) {
    errors.password = "Passwords do not match.";
    errors.confirmPassword = "Passwords do not match.";
  }

  // recaptcha
  if (values.recaptcha === "noKey" && RECAPTCHA_SITEKEY) {
    errors.recaptcha = "Required";
  }

  console.debug(errors);
  return errors;
};

// Component
export default function ResetPassword() {
  console.debug("ResetPassword rendered!");

  // page title
  useTitle("IntelOwl | Reset Password", { restoreOnUnmount: true });

  const [passwordShown, setPasswordShown] = React.useState(false);

  // react router's history
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // get query parameter "key" (key should be an UUID v4)
  const [key, isKeyValid] = React.useMemo(() => {
    const qpKey = searchParams.get("key") || null;
    return [qpKey, reMatcher.test(qpKey)];
  }, [searchParams]);

  // callbacks
  const onSubmit = React.useCallback(
    async (values) => {
      const body = {
        key,
        password: values.password,
        recaptcha: values.recaptcha,
      };
      try {
        await resetPassword(body);
        // just to give small lag
        setTimeout(() => navigate("/login"), 500);
      } catch (e) {
        // handled inside resetPassword
      }
    },
    [key, navigate]
  );

  return (
    <ContentSection className="bg-body">
      {isKeyValid ? (
        <ContentSection className="col-lg-4 mx-auto">
          <h3 className="font-weight-bold">Reset password</h3>
          <hr />
          {/* Form */}
          <Formik
            initialValues={initialValues}
            validate={onValidate}
            onSubmit={onSubmit}
            validateOnMount
          >
            {(formik) => (
              <Form>
                {/* Password */}
                <FormGroup row>
                  <Col sm={12} md={12}>
                    <Label
                      className="form-control-label required"
                      htmlFor="password"
                    >
                      New Password
                    </Label>
                    <Input
                      name="password"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Create a strong password..."
                      autoComplete="new-password"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      valid={!formik.errors.password}
                      invalid={
                        formik.errors.password && formik.touched.password
                      }
                    />
                    {formik.touched.password && (
                      <small>{formik.errors.password}</small>
                    )}
                  </Col>
                </FormGroup>
                <FormGroup row>
                  <Col sm={12} md={12}>
                    <Label
                      className="form-control-label required"
                      htmlFor="confirmPassword"
                    >
                      Confirm New Password
                    </Label>
                    <Input
                      name="confirmPassword"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Re-enter password"
                      autoComplete="new-password"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      valid={!formik.errors.confirmPassword}
                      invalid={
                        formik.errors.confirmPassword &&
                        formik.touched.confirmPassword
                      }
                    />
                    {formik.touched.confirmPassword && (
                      <small>{formik.errors.confirmPassword}</small>
                    )}
                  </Col>
                </FormGroup>
                <FormGroup check>
                  <Input
                    id="RegisterForm__showPassword"
                    type="checkbox"
                    defaultChecked={passwordShown}
                    onChange={() => setPasswordShown(!passwordShown)}
                  />
                  <Label check>Show password</Label>
                </FormGroup>
                {/* reCAPTCHA */}
                <FormGroup className="mt-3 d-flex">
                  {RECAPTCHA_SITEKEY && (
                    <ReCAPTCHAInput
                      id="RegisterForm__recaptcha"
                      className="m-3 mx-auto"
                    />
                  )}
                </FormGroup>
                {/* Submit */}
                <FormGroup className="mt-3 d-flex">
                  <Button
                    type="submit"
                    disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                    className="mx-auto"
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Submit
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
      ) : (
        <h5 className="text-center">Error: Invalid key.</h5>
      )}
    </ContentSection>
  );
}
