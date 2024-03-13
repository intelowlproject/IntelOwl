import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Login from "../../../src/components/auth/Login";
import { AUTH_BASE_URI } from "../../../src/constants/apiURLs";

jest.mock("axios");
jest.mock("../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "",
}));

describe("Login component", () => {
  // mock login request
  axios.post.mockImplementation({});

  test("User login", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>,
    );

    // page before login
    const usernameInputElement = screen.getByLabelText("Username");
    expect(usernameInputElement).toBeInTheDocument();
    const passwordInputElement = screen.getByLabelText("Password");
    expect(passwordInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Login/i });
    expect(submitButtonElement).toBeInTheDocument();
    const forgotPasswordElement = screen.getByText("Forgot Password?");
    expect(forgotPasswordElement).toBeInTheDocument();
    const verificationEmailElement = screen.getByText(
      "Need Verification Email?",
    );
    expect(verificationEmailElement).toBeInTheDocument();

    // user populates the login form and submit
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "dummyPwd1");
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(
        `${AUTH_BASE_URI}/login`,
        { password: "dummyPwd1", username: "test_user", recaptcha: "noKey" },
        { certegoUIenableProgressBar: false },
      );
      // check redirect to home page
      expect(global.location.pathname).toEqual("/");
    });
  });
});
