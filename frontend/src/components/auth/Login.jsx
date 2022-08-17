import React from "react";
import { useSearchParams } from "react-router-dom";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
  Row,
} from "reactstrap";
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
  useTitle("IntelOwl | Login", { restoreOnUnmount: true });

  // local state
  const [passwordShown, setPasswordShown] = React.useState(false);

  // auth store
  const loginUser = useAuthStore(
    React.useCallback((s) => s.service.loginUser, [])
  );

  const updateToken = useAuthStore(React.useCallback((s) => s.updateToken, []));

  // callbacks
  const onSubmit = React.useCallback(
    async (values, _formik) => {
      try {
        await loginUser(values);
      } catch (e) {
        // handled inside loginUser
      }
    },
    [loginUser]
  );

  const [searchParams] = useSearchParams();
  if (searchParams.get("token")) updateToken(searchParams.get("token"));

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4">
        <div className="g-0 my-2 d-none d-md-flex">
          <img
            src={`${PUBLIC_URL}/logo-negative.png`}
            alt="IntelOwl Logo"
            className="img-fluid w-75 mx-auto"
          />
        </div>
        <ContentSection>
          <Row>
            <h3 className="fw-bold col-auto me-auto mt-2">Log In</h3>
            <a href="/api/auth/google" className="col-auto">
              <button type="button" className="bg-transparent border-0">
                <img
                  src={`${PUBLIC_URL}/google-logo.svg`}
                  alt="Google Logo"
                  className="img-fluid"
                />
              </button>
            </a>
          </Row>
          <hr />
          {/* Form */}
          <Formik
            initialValues={initialValues}
            validate={onValidate}
            onSubmit={onSubmit}
            validateOnChange
          >
            {(formik) => (
              <Form>
                {/* username */}
                <FormGroup>
                  <Label for="LoginForm__username">Username</Label>
                  <Input
                    id="LoginForm__username"
                    type="text"
                    name="username"
                    placeholder="Enter username"
                    autoComplete="username"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label for="LoginForm__password">Password</Label>
                  <Input
                    id="LoginForm__password"
                    type={passwordShown ? "text" : "password"}
                    name="password"
                    placeholder="Enter password"
                    autoComplete="current-password"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                <FormGroup check>
                  <Input
                    id="LoginForm__showPassword"
                    type="checkbox"
                    defaultChecked={passwordShown}
                    onChange={() => setPasswordShown(!passwordShown)}
                  />
                  <Label check>Show password</Label>
                </FormGroup>
                <div className="text-muted mb-3">
                  Don&apos;t have an account? Contact the administrator for
                  access.
                </div>
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Button
                    type="submit"
                    disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Login
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
      </Container>
    </ContentSection>
  );
}
