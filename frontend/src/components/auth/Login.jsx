import React from "react";
import { FormGroup, Label, Container, CustomInput, Row } from "reactstrap";
import { CustomInput as FormInput, Submit } from "formstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";

import { PUBLIC_URL } from "../../constants/environment";
import { useAuthStore } from "../../stores";

// constants
const initialValues = {
  username: "",
  password: "",
};
// methods
const onValidate = (values) => {
  const errors = {};
  if (!values.username) {
    errors.username = "Required";
  }
  if (!values.password) {
    errors.password = "Required";
  }
  return errors;
};

// Component
export default function Login() {
  console.debug("Login rendered!");

  // page title
  useTitle("IntelOwl | Login", { restoreOnUnmount: true, });

  // local state
  const [passwordShown, setPasswordShown] = React.useState(false);

  // auth store
  const loginUser = useAuthStore(
    React.useCallback((s) => s.service.loginUser, [])
  );

  // callbacks
  const onSubmit = React.useCallback(
    async (values, formik) => {
      try {
        await loginUser(values);
      } catch (e) {
        // handled inside loginUser
      }
    },
    [loginUser]
  );

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4">
        <Row noGutters className="my-2 d-none d-md-flex">
          <img
            src={`${PUBLIC_URL}/logo-negative.png`}
            alt="IntelOwl Logo"
            className="img-fluid w-75 mx-auto"
          />
        </Row>
        <ContentSection>
          <h3 className="font-weight-bold">Log In</h3>
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
                {/* username */}
                <FormGroup>
                  <Label className="form-control-label" htmlFor="username">
                    Username
                  </Label>
                  <FormInput
                    id="LoginForm__username"
                    type="text"
                    name="username"
                    className="form-control"
                    placeholder="Enter username"
                    autoComplete="username"
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label className="form-control-label" htmlFor="password">
                    Password
                  </Label>
                  <FormInput
                    id="LoginForm__password"
                    type={passwordShown ? "text" : "password"}
                    name="password"
                    className="form-control"
                    placeholder="Enter password"
                    autoComplete="current-password"
                  />
                  <CustomInput
                    id="LoginForm__showPassword"
                    type="checkbox"
                    defaultChecked={passwordShown}
                    onChange={() => setPasswordShown(!passwordShown)}
                    label="Show password"
                    className="mt-2 form-control-sm d-flex-start-center"
                  />
                  <span className="text-muted">
                    Don't have an account? Contact the administrator for access.
                  </span>
                </FormGroup>
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Submit
                    withSpinner
                    disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                  >
                    {!formik.isSubmitting && "Login"}
                  </Submit>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
      </Container>
    </ContentSection>
  );
}
