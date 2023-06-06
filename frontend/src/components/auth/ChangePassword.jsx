// import axios from "axios";
import React from "react";
// import { AiOutlineInfoCircle } from "react-icons/ai";
import { useSearchParams } from "react-router-dom";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
  Row,
  // Tooltip,
} from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection } from "@certego/certego-ui";
// import { AUTH_BASE_URI } from "../../constants/api";

// import { PUBLIC_URL } from "../../constants/environment";
import { useAuthStore } from "../../stores";

import {
  ResendVerificationEmailButton,
  ForgotPasswordButton,
} from "./utils/registration-buttons";

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
export default function ChangePassword() {
  console.debug("Login rendered!");

  // const [isOpen, setIsOpen] = React.useState(false);

  // page title
  useTitle("IntelOwl | ChangePassword", { restoreOnUnmount: true });

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
    <ContentSection className="pt-20">
      <Container className="col-12 col-lg-8 col-xl-4">
        <ContentSection>
          <Row>
            <h3 className="fw-bold col-auto me-auto mt-2">Change Password</h3>
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
                  <Label for="LoginForm__password">Old Password</Label>
                  <Input
                    id="LoginForm__password"
                    type="text"
                    name="password"
                    placeholder="Enter old password"
                    // autoComplete="current-password"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label for="LoginForm__password">New Password</Label>
                  <Input
                    id="LoginForm__password"
                    type={passwordShown ? "text" : "password"}
                    name="password"
                    placeholder="Enter new password"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                <FormGroup>
                  <Label for="LoginForm__password">Confirm Password</Label>
                  <Input
                    id="LoginForm__password"
                    type={passwordShown ? "text" : "password"}
                    name="password"
                    placeholder="Enter new password"
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
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Button
                    type="submit"
                    // disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Change
                    Password
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
        {/* popover buttons */}
        <Row className="d-flex flex-column align-items-end g-0">
          <ForgotPasswordButton />
          <ResendVerificationEmailButton />
        </Row>
      </Container>
    </ContentSection>
  );
}
