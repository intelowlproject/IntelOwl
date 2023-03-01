import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import EmailVerification from "../../../src/components/auth/EmailVerification";

jest.mock("axios");
jest.mock("../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "",
}));

describe("EmailVerification component", () => {
  test("Test valid key", async () => {
    render(
      <MemoryRouter initialEntries={["/verify-email?key=testkey"]}>
        <EmailVerification />
      </MemoryRouter>
    );

    const element = screen.getByText("Verifying...");
    expect(element).toBeInTheDocument();
  });

  test("Test invalid key", () => {
    render(
      <MemoryRouter initialEntries={["/verify-email?key="]}>
        <EmailVerification />
      </MemoryRouter>
    );

    const element = screen.getByText("Error: Invalid key.");
    expect(element).toBeInTheDocument();
  });
});
