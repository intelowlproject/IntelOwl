import React from "react";
import { Link as RRLink } from "react-router-dom";
import {
  Container,
  Row,
  Col,
  FormGroup,
  Label,
  Spinner,
  Input,
  InputGroup,
  Button,
  InputGroupText,
} from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection, Select } from "@certego/certego-ui";

import { PUBLIC_URL, RECAPTCHA_SITEKEY } from "../../constants/environment";
import { HACKER_MEME_STRING, EMAIL_REGEX } from "../../constants";
import ReCAPTCHAInput from "./utils/ReCAPTCHAInput";
import { AfterRegistrationModalAlert, InviteOnlyAlert } from "./utils/utils";
import { registerUser } from "./api";

// constants
const hearAboutUsChoices = [
  {
    label: "Search Engine (Google, DuckDuckGo, etc.)",
    value: "search_engine",
  },
  {
    label: "Recommended by friend or colleague",
    value: "was_recommended",
  },
  {
    label: "Social media",
    value: "social_media",
  },
  {
    label: "Blog or Publication",
    value: "blog_or_publication",
  },
  {
    label: "Other",
    value: "other",
  },
];

const REGISTRATION_FORM_STORAGE_KEY = "registrationForm";
const initialValues = JSON.parse(
  localStorage.getItem(REGISTRATION_FORM_STORAGE_KEY, "{}")
) || {
  first_name: "",
  last_name: "",
  email: "",
  username: "",
  password: "",
  confirmPassword: "",
  company_name: "",
  company_role: "",
  twitter_handle: "",
  discover_from: "other",
  recaptcha: "noKey",
};

const onValidate = (values) => {
  const errors = {};

  // static text fields
  const textFields = ["first_name", "last_name", "username"];
  textFields.forEach((field) => {
    if (!values[field]) {
      errors[field] = "Required";
    } else if (values[field].length > 15) {
      errors[field] = "Must be 15 characters or less";
    } else if (values[field].length < 4) {
      errors[field] = "Must be 4 characters or more";
    }
  });
  if (
    ["administrator", "admin", "certego", "hacker"].indexOf(values.username) !==
    -1
  ) {
    errors.username = HACKER_MEME_STRING;
  }
  if (!values.email) {
    errors.email = "Required";
  } else if (!EMAIL_REGEX.test(values.email)) {
    errors.email = "Invalid email address";
  }
  ["company_name", "company_role"].forEach((field) => {
    if (!values[field]) {
      errors[field] = "Required";
    } else if (values[field].length > 30) {
      errors[field] = "Must be 30 characters or less";
    } else if (values[field].length < 3) {
      errors[field] = "Must be 3 characters or more";
    }
  });

  // store in localStorage so user doesn't have to fill all fields again
  if (Object.keys(errors).length === 0) {
    localStorage.setItem(
      REGISTRATION_FORM_STORAGE_KEY,
      JSON.stringify({
        ...values,
        password: "",
        confirmPassword: "",
        recaptcha: "noKey",
      })
    );
  }

  // password fields
  if (!values.password) {
    errors.password = "Required";
  } else if (values.password.length < 8) {
    errors.password = "Must be 8 characters or more";
  }
  if (!values.confirmPassword) {
    errors.confirmPassword = "Required";
  } else if (values.confirmPassword.length < 8) {
    errors.confirmPassword = "Must be 8 characters or more";
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
export default function Register() {
  console.debug("Register rendered!");

  // page title
  useTitle("IntelOwl | Sign up", { restoreOnUnmount: true });

  // local state
  const [showModal, setShowModal] = React.useState(false);
  const [passwordShown, setPasswordShown] = React.useState(false);

  console.debug(showModal);

  // callbacks
  const onSubmit = React.useCallback(
    async (values) => {
      const reqBody = {
        first_name: values.first_name,
        last_name: values.last_name,
        username: values.username,
        email: values.email,
        password: values.password,
        recaptcha: values.recaptcha,
        profile: {
          company_name: values.company_name,
          company_role: values.company_role,
          twitter_handle: values.twitter_handle,
          discover_from: values.discover_from,
        },
      };
      try {
        await registerUser(reqBody);
        setShowModal(true);
      } catch (e) {
        // handled inside registerUser
      }
    },
    [setShowModal]
  );

  return (
    <ContentSection className="bg-body">
      {showModal && (
        <AfterRegistrationModalAlert
          isOpen={showModal}
          setIsOpen={setShowModal}
        />
      )}
      <Container fluid className="col-12">
        {/* IntelOwl Logo */}
        <Row className="g-0 my-2 d-none d-md-flex">
          <img
            src={`${PUBLIC_URL}/logo-negative.png`}
            alt="IntelOwl Logo"
            className="img-fluid w-25 mx-auto"
          />
        </Row>
        <Row className="g-0">
          <InviteOnlyAlert />
        </Row>
        <ContentSection className="col-12 col-lg-10 col-xl-5 mx-auto">
          <Row>
            <h3 className="font-weight-bold">Register</h3>
          </Row>
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
                {/* Name */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="first_name"
                    >
                      First Name
                    </Label>
                    <Input
                      name="first_name"
                      type="text"
                      className="form-control"
                      placeholder="Jane"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.first_name !== "Required" ? (
                      <div>{formik.errors.first_name}</div>
                    ) : null}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="last_name"
                    >
                      Last Name
                    </Label>
                    <Input
                      name="last_name"
                      type="text"
                      className="form-control"
                      placeholder="Doe"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.last_name !== "Required" ? (
                      <div>{formik.errors.last_name}</div>
                    ) : null}
                  </Col>
                </FormGroup>
                {/* Email/Username */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="email"
                    >
                      Email
                    </Label>
                    <Input
                      name="email"
                      type="email"
                      className="form-control"
                      placeholder="jane@example.com"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.email !== "Required" ? (
                      <div>{formik.errors.email}</div>
                    ) : null}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="username"
                    >
                      Username
                    </Label>
                    <Input
                      name="username"
                      type="text"
                      className="form-control"
                      placeholder="janedoe"
                      autoComplete="username"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.username !== "Required" ? (
                      <div>{formik.errors.username}</div>
                    ) : null}
                  </Col>
                </FormGroup>
                {/* Password */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="password"
                    >
                      Password
                    </Label>
                    <Input
                      name="password"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Create a strong password..."
                      autoComplete="new-password"
                      valid={!formik.errors.password}
                      onChange={formik.handleChange}
                    />
                    {formik.errors.password !== "Required" ? (
                      <div>{formik.errors.password}</div>
                    ) : null}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="confirmPassword"
                    >
                      Confirm Password
                    </Label>
                    <Input
                      name="confirmPassword"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Re-enter password"
                      autoComplete="new-password"
                      valid={!formik.errors.confirmPassword}
                      onChange={formik.handleChange}
                    />
                    {formik.errors.confirmPassword !== "Required" ? (
                      <div>{formik.errors.confirmPassword}</div>
                    ) : null}
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
                <Col sm={12} md={12} className="text-center standout alert">
                  We ask you to provide the following information to better
                  understand what you intend to use IntelOwl for
                </Col>
                {/* Extra fields */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="company_name"
                    >
                      Company/ Organization
                    </Label>
                    <Input
                      name="company_name"
                      type="text"
                      className="form-control"
                      placeholder="E Corp"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.company_name !== "Required" ? (
                      <div>{formik.errors.company_name}</div>
                    ) : null}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="company_role"
                    >
                      Role
                    </Label>
                    <Input
                      name="company_role"
                      type="text"
                      className="form-control"
                      placeholder="Researcher"
                      onChange={formik.handleChange}
                    />
                    {formik.errors.company_role !== "Required" ? (
                      <div>{formik.errors.company_role}</div>
                    ) : null}
                  </Col>
                </FormGroup>
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label"
                      htmlFor="twitter_handle"
                    >
                      Twitter Handle (optional)
                    </Label>
                    <InputGroup>
                      <InputGroupText>@</InputGroupText>
                      <Input
                        name="twitter_handle"
                        type="text"
                        className="form-control"
                        placeholder="intelowl"
                        onChange={formik.handleChange}
                      />
                    </InputGroup>
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="discover_from"
                    >
                      How did you discover IntelOwl ?
                    </Label>
                    <Select
                      name="discover_from"
                      choices={hearAboutUsChoices}
                      onChange={formik.handleChange}
                    />
                  </Col>
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
                    {formik.isSubmitting && <Spinner size="sm" />} Register
                  </Button>
                </FormGroup>
                <p className="text-muted">
                  By signing up, you accept our{" "}
                  <RRLink to="" className="link-ul-muted">
                    Terms of Use
                  </RRLink>
                  , articles 3, 4, 7, 9 of the Terms of Use, and the{" "}
                  <RRLink to="" className="link-ul-muted">
                    Privacy and Cookie Policy
                  </RRLink>
                </p>
              </Form>
            )}
          </Formik>
        </ContentSection>
      </Container>
    </ContentSection>
  );
}
