import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import { AUTH_BASE_URI } from "../../../src/constants/api";
import Logout from "../../../src/components/auth/Logout";

jest.mock("axios");

describe("Logout component", () => {
  // mock login request
  axios.post.mockImplementation(() => Promise.resolve());

  test("User logout", async () => {
    render(
      <BrowserRouter>
        <Logout />
      </BrowserRouter>
    );

    expect(axios.post).toHaveBeenCalledWith(`${AUTH_BASE_URI}/logout`, null, {
      certegoUIenableProgressBar: false,
    });
    expect(screen.getByText("Logging you out...")).toBeInTheDocument();
  });
});
