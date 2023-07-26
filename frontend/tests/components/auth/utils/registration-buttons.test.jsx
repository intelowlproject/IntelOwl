import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router-dom";
import {
  ResendVerificationEmailButton,
  ForgotPasswordButton,
} from "../../../../src/components/auth/utils/registration-buttons";

describe("registration-button", () => {
  test("ResendVerificationEmailButton component", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ResendVerificationEmailButton />
      </BrowserRouter>,
    );

    const buttonElement = screen.getByRole("button");
    expect(buttonElement).toBeInTheDocument();
    expect(buttonElement).toHaveTextContent("Need Verification Email?");

    await user.click(buttonElement);

    await waitFor(() => {
      const popOverElement = screen.getByText(
        "We will shoot you an email with instructions to verify your email address.",
      );
      expect(popOverElement).toBeInTheDocument();
    });
  });

  test("ForgotPasswordButton component", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ForgotPasswordButton />
      </BrowserRouter>,
    );

    const buttonElement = screen.getByRole("button");
    expect(buttonElement).toBeInTheDocument();
    expect(buttonElement).toHaveTextContent("Forgot Password?");

    await user.click(buttonElement);

    await waitFor(() => {
      const popOverElement = screen.getByText(
        "We will shoot you an email with instructions to reset your password.",
      );
      expect(popOverElement).toBeInTheDocument();
    });
  });
});
