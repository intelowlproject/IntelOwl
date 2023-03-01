import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import EmailForm from "../../../../src/components/auth/utils/EmailForm";

jest.mock("axios");
jest.mock("../../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "",
}));

describe("EmailForm component", () => {
  test("Submit email form", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();
    const mockApi = jest.fn();

    render(
      <BrowserRouter>
        <EmailForm apiCallback={mockApi} onFormSubmit={jest.fn()} />
      </BrowserRouter>
    );

    const emailInputElement = screen.getByLabelText("Email Address");
    expect(emailInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Send/i });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the reset password form and submit
    await user.type(emailInputElement, "test@test.com");
    await user.click(submitButtonElement);
  });
});
