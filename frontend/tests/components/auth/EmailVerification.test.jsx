import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
// import axios from "axios";
// import { AUTH_BASE_URI } from "../../../src/constants/api";
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

    // await waitFor(() => {
    //   // check request has been performed
    //   expect(axios.post).toHaveBeenCalledWith(
    //     `${AUTH_BASE_URI}/verify-email`, {key: "testkey"},
    //   );
    // });

    const element = screen.getByText("Verifying...");
    expect(element).toBeInTheDocument();

    // await waitFor(() => {
    //   // check redirect to "/login"
    //   expect(global.location.pathname).toEqual("/login");
    // });
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
