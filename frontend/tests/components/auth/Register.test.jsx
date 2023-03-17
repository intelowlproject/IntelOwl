import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Register from "../../../src/components/auth/Register";
import { AUTH_BASE_URI } from "../../../src/constants/api";

jest.mock("axios");
jest.mock("../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "",
}));

describe("Registration component", () => {
  beforeEach(() => {
    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>
    );
  });

  test("User registration", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    // page before registration
    const firstNameInputElement = screen.getByLabelText("First Name");
    expect(firstNameInputElement).toBeInTheDocument();
    const lastNameInputElement = screen.getByLabelText("Last Name");
    expect(lastNameInputElement).toBeInTheDocument();
    const emailInputElement = screen.getByLabelText("Email");
    expect(emailInputElement).toBeInTheDocument();
    const usernameInputElement = screen.getByLabelText("Username");
    expect(usernameInputElement).toBeInTheDocument();
    const passwordInputElement = screen.getByLabelText("Password");
    expect(passwordInputElement).toBeInTheDocument();
    const confirmPasswordInputElement =
      screen.getByLabelText("Confirm Password");
    expect(confirmPasswordInputElement).toBeInTheDocument();
    const companyNameInputElement = screen.getByLabelText(
      "Company/ Organization"
    );
    expect(companyNameInputElement).toBeInTheDocument();
    const companyRoleInputElement = screen.getByLabelText("Role");
    expect(companyRoleInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", {
      name: /Register/i,
    });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the registration form and submit
    await user.type(firstNameInputElement, "firstname");
    await user.type(lastNameInputElement, "lastname");
    await user.type(emailInputElement, "test@test.com");
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "intelowlpassword");
    await user.type(confirmPasswordInputElement, "intelowlpassword");
    await user.type(companyNameInputElement, "companyname");
    await user.type(companyRoleInputElement, "companyrole");
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(`${AUTH_BASE_URI}/register`, {
        first_name: "firstname",
        last_name: "lastname",
        username: "test_user",
        email: "test@test.com",
        password: "intelowlpassword",
        recaptcha: "noKey",
        profile: {
          company_name: "companyname",
          company_role: "companyrole",
          twitter_handle: "",
          discover_from: "other",
        },
      });
    });
  });

  test("Show password checkbox", async () => {
    const user = userEvent.setup();

    const checkBoxElement = screen.getByRole("checkbox");
    expect(checkBoxElement).toBeInTheDocument();
    expect(checkBoxElement).not.toBeChecked();

    await user.click(checkBoxElement);

    await waitFor(() => {
      expect(checkBoxElement).toBeChecked();
    });
  });
});
