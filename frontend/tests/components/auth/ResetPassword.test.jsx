import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import { AUTH_BASE_URI } from "../../../src/constants/api";
import ResetPassword from "../../../src/components/auth/ResetPassword";

jest.mock("axios");
jest.mock("../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "",
}));

describe("ResetPassword component", () => {
  test("Test valid key", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    render(
      <MemoryRouter
        initialEntries={[
          "/reset-password?key=c0236120-c905-4534-b8ba-aca5e94aa5da",
        ]}
      >
        <ResetPassword />
      </MemoryRouter>
    );

    // page before reset password
    const passwordInputElement = screen.getByLabelText("New Password");
    expect(passwordInputElement).toBeInTheDocument();
    const confirmPasswordInputElement = screen.getByLabelText(
      "Confirm New Password"
    );
    expect(confirmPasswordInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Submit/i });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the reset password form and submit
    await user.type(passwordInputElement, "NewPassword1234");
    await user.type(confirmPasswordInputElement, "NewPassword1234");
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(
        `${AUTH_BASE_URI}/reset-password`,
        {
          key: "c0236120-c905-4534-b8ba-aca5e94aa5da",
          password: "NewPassword1234",
          recaptcha: "noKey",
        }
      );
    });
  });

  test("Test invalid key", () => {
    render(
      <MemoryRouter
        initialEntries={["/reset-password?key=c0236120-c905-4534-b8ba"]}
      >
        <ResetPassword />
      </MemoryRouter>
    );

    const element = screen.getByText("Error: Invalid key.");
    expect(element).toBeInTheDocument();
  });
});
