import React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { FormGroup, Label, Col, Input, Button, Spinner } from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";

import { UUID_REGEX } from "../../constants/index";
import ReCAPTCHAInput from "./utils/ReCAPTCHAInput";
import { resetPassword } from "./api";
import { RECAPTCHA_SITEKEY } from "../../constants/environment";
import {
  PasswordValidator,
  RecaptchaValidator,
  ComparePassword,
} from "./utils/validator";

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
  const passwordErrors = PasswordValidator(values.password);
  if (passwordErrors.password) {
    errors.password = passwordErrors.password;
  }
  const confirmPasswordErrors = PasswordValidator(values.confirmPassword);
  if (confirmPasswordErrors.password) {
    errors.confirmPassword = confirmPasswordErrors.password;
  }
  const comparePasswordErrors = ComparePassword(
    values.password,
    values.confirmPassword
  );
  if (comparePasswordErrors.password) {
    errors.password = comparePasswordErrors.password;
  }
  if (comparePasswordErrors.confirmPassword) {
    errors.confirmPassword = comparePasswordErrors.confirmPassword;
  }

  // recaptcha
  const recaptchaErrors = RecaptchaValidator(values.recaptcha);
  if (recaptchaErrors.recaptcha) {
    errors.recaptcha = recaptchaErrors.recaptcha;
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
                      htmlFor="ResetPassword__password"
                    >
                      New Password
                    </Label>
                    <Input
                      id="ResetPassword__password"
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
                      htmlFor="ResetPassword__confirmPassword"
                    >
                      Confirm New Password
                    </Label>
                    <Input
                      id="ResetPassword__confirmPassword"
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
                    id="ResetPassword__showPassword"
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
                      id="ResetPassword__recaptcha"
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
