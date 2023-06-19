import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router-dom";
import {
  InviteOnlyAlert,
  AfterRegistrationModalAlert,
  ConfigurationModalAlert,
} from "../../../../src/components/auth/utils/registration-alert";

describe("registration-alert", () => {
  test("InviteOnlyAlert component", () => {
    render(
      <BrowserRouter>
        <InviteOnlyAlert />
      </BrowserRouter>
    );

    const titleElement = screen.getByText(
      "Sign up below to join the waitlist!"
    );
    expect(titleElement).toBeInTheDocument();
  });

  test("AfterRegistrationModalAlert component", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <AfterRegistrationModalAlert isOpen setIsOpen={jest.fn()} />
      </BrowserRouter>
    );

    const elementText = screen.getByText("Registration successful! 🥳");
    expect(elementText).toBeInTheDocument();
    const buttonElement = screen.getByRole("button");
    expect(buttonElement).toBeInTheDocument();

    await user.click(buttonElement);

    await waitFor(() => {
      // check redirect to "/"
      expect(global.location.pathname).toEqual("/");
    });
  });

  test("ConfigurationModalAlert component", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ConfigurationModalAlert
          isOpen
          setIsOpen={jest.fn()}
          title="The Registration Feature has not been configured!"
        />
      </BrowserRouter>
    );

    const elementText = screen.getByText("Warning");
    expect(elementText).toBeInTheDocument();
    const elementAlertText = screen.getByText(
      "The Registration Feature has not been configured!"
    );
    expect(elementAlertText).toBeInTheDocument();
    const buttonElement = screen.getByRole("button");
    expect(buttonElement).toBeInTheDocument();

    await user.click(buttonElement);

    await waitFor(() => {
      // check redirect to "/"
      expect(global.location.pathname).toEqual("/");
    });
  });
});
