import axios from "axios";
import React from "react";
import { AiOutlineInfoCircle } from "react-icons/ai";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
  Row,
  Tooltip,
} from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { addToast, ContentSection } from "@certego/certego-ui";
import { AUTH_BASE_URI } from "../../constants/apiURLs";

import { PUBLIC_URL, RECAPTCHA_SITEKEY } from "../../constants/environment";
import ReCAPTCHAInput from "./utils/ReCAPTCHAInput";
import { RecaptchaValidator } from "./utils/validator";
import { ConfigurationModalAlert } from "./utils/registration-alert";
import { useAuthStore } from "../../stores/useAuthStore";
import { checkConfiguration } from "./authApi";

import {
  ResendVerificationEmailButton,
  ForgotPasswordButton,
} from "./utils/registration-buttons";

// constants
const initialValues = {
  username: "",
  password: "",
  recaptcha: "noKey",
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
  // recaptcha
  const recaptchaErrors = RecaptchaValidator(values.recaptcha);
  if (recaptchaErrors.recaptcha) {
    errors.recaptcha = recaptchaErrors.recaptcha;
  }
  return errors;
};

// Component
export default function Login() {
  console.debug("Login rendered!");

  const [isOpen, setIsOpen] = React.useState(false);

  // page title
  useTitle("IntelOwl | Login", { restoreOnUnmount: true });

  // local state
  const [passwordShown, setPasswordShown] = React.useState(false);
  const [showConfigurationModal, setShowConfigurationModal] =
    React.useState(false);

  React.useEffect(() => {
    checkConfiguration({
      params: {
        page: "login",
      },
    }).catch(() => {
      setShowConfigurationModal(true);
    });
  }, []);

  console.debug("showConfigurationModal:", showConfigurationModal);

  // auth store
  const loginUser = useAuthStore(
    React.useCallback((state) => state.service.loginUser, []),
  );

  // callbacks
  const onSubmit = React.useCallback(
    async (values, _formik) => {
      try {
        await loginUser(values);
      } catch (error) {
        // handled inside loginUser
      }
    },
    [loginUser],
  );

  return (
    <ContentSection className="bg-body">
      {showConfigurationModal && (
        <ConfigurationModalAlert
          isOpen={showConfigurationModal}
          setIsOpen={setShowConfigurationModal}
          title="The Recaptcha has not been configured!"
        />
      )}
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
            <div className="col-auto">
              <a
                href={`${AUTH_BASE_URI}/google`}
                onClick={(event) => {
                  event.preventDefault();
                  const url = `${AUTH_BASE_URI}/google`;
                  axios
                    .get(`${url}?no_redirect=true`)
                    .then(() => {
                      window.location = url;
                    })
                    .catch((error) => {
                      if (
                        error?.response?.status === 401 &&
                        error.parsedMsg.includes("OAuth is not configured.")
                      )
                        addToast(
                          "Login failed!",
                          "OAuth is not configured. " +
                            "Check documentation to set it up.",
                          "danger",
                          true,
                        );
                      else throw error;
                    });
                }}
              >
                <img
                  src={`${PUBLIC_URL}/google-logo.svg`}
                  alt="Google Logo"
                  className="img-fluid"
                />
              </a>
              <AiOutlineInfoCircle
                style={{ verticalAlign: "top" }}
                id="GoogleInfoTooltip"
                cursor="pointer"
              />
              <Tooltip
                placement="top"
                isOpen={isOpen}
                target="GoogleInfoTooltip"
                toggle={() => {
                  setIsOpen(!isOpen);
                }}
              >
                Check the Authentication section in the documentation for
                enabling Google Authentication.
              </Tooltip>
            </div>
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
                {/* reCAPTCHA */}
                <FormGroup className="mt-3 d-flex">
                  {RECAPTCHA_SITEKEY && (
                    <ReCAPTCHAInput
                      id="LoginForm__recaptcha"
                      className="m-3 mx-auto"
                    />
                  )}
                </FormGroup>
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
        {/* popover buttons */}
        <Row className="d-flex flex-column align-items-end g-0">
          <ForgotPasswordButton />
          <ResendVerificationEmailButton />
        </Row>
      </Container>
    </ContentSection>
  );
}
