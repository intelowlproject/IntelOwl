import React from "react";
// import PropTypes from "prop-types";
import { Alert, PopoverBody } from "reactstrap";
import { IoMail } from "react-icons/io5";
import { PopupFormButton } from "@certego/certego-ui";
import EmailForm from "./EmailForm";
import { resendVerificationMail, requestPasswordReset } from "../api";

function Icon(text) {
  return (
    <small className="d-flex-center standout">
      <IoMail />
      &nbsp;
      <span>{text}</span>
    </small>
  );
}

function FormPopoverBody(formProps, text, api) {
  return (
    <PopoverBody>
      <Alert className="mb-4 text-wrap" color="secondary">
        <IoMail />
        &nbsp;{text}
      </Alert>
      <EmailForm
        className="col-lg-6 col-sm-12"
        apiCallback={api}
        {...formProps}
      />
    </PopoverBody>
  );
}

function EmailIcon() {
  return Icon("Need Verification Email?");
}

function EmailFormPopoverBody(formProps) {
  return FormPopoverBody(
    formProps,
    "We will shoot you an email with instructions to verify your email address.",
    resendVerificationMail,
  );
}

// Popover Button for "Request Verification Email?"
export function ResendVerificationEmailButton() {
  return (
    <PopupFormButton
      id="reqverificationemail-iconbtn"
      popOverPlacement="top-start"
      Icon={EmailIcon}
      Form={EmailFormPopoverBody}
      size="sm"
      outline
      className="border-0"
    />
  );
}

function PasswordIcon() {
  return Icon("Forgot Password?");
}

function PasswordFormPopoverBody(formProps) {
  return FormPopoverBody(
    formProps,
    "We will shoot you an email with instructions to reset your password.",
    requestPasswordReset,
  );
}

// Popover Button for "Forgot Password?"
export function ForgotPasswordButton() {
  return (
    <PopupFormButton
      id="requestpasswordreset-iconbtn"
      popOverPlacement="top-start"
      Icon={PasswordIcon}
      Form={PasswordFormPopoverBody}
      size="sm"
      outline
      className="border-0"
    />
  );
}
