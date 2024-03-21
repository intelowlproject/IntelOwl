import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";

import useAxios from "axios-hooks";
import axios from "axios";
import userEvent from "@testing-library/user-event";

import TokenAccess from "../../../../src/components/user/token/TokenAccess";
import { APIACCESS_BASE_URI } from "../../../../src/constants/apiURLs";

jest.mock("axios");
jest.mock("axios-hooks");

describe("test TokenAccess", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          key: "987654321",
          created: "2024-02-22T18:48:18.257944",
        },
      }),
    );
    axios.delete.mockImplementation(() =>
      Promise.resolve({
        data: {},
      }),
    );
  });

  test("render with token", async () => {
    useAxios.mockImplementation(() => [
      {
        data: {
          key: "123456789",
          created: "2024-02-22T15:48:18.257944",
        },
        loading: false,
        error: "",
      },
    ]);

    const user = userEvent.setup();

    const result = render(<TokenAccess />);
    expect(screen.getByText("Created")).toBeInTheDocument();
    expect(screen.getByText("03:48 PM Feb 22nd, 2024")).toBeInTheDocument();

    // test user interaction
    const showButton = result.container.querySelector(
      "#toggle-show-apikey-btn",
    );
    expect(showButton).toBeInTheDocument();
    await user.click(showButton);
    expect(screen.getByText("123456789")).toBeInTheDocument();
  });

  test("render without token", () => {
    useAxios.mockImplementation(() => [
      {
        data: undefined,
        loading: false,
        error: { response: { status: 404 }, errors: { detail: "Not found." } },
      },
    ]);

    render(<TokenAccess />);

    expect(screen.getByText("No active API key")).toBeInTheDocument();
  });

  test("delete token", async () => {
    useAxios
      .mockImplementation(() => [
        {
          data: {
            key: "987654321",
            created: "2024-02-22T18:48:18.257944",
          },
          loading: false,
          error: "",
        },
      ])
      .mockImplementationOnce(() => [
        {
          data: {
            key: "123456789",
            created: "2024-02-22T15:48:18.257944",
          },
          loading: false,
          error: "",
        },
      ]);

    const user = userEvent.setup();

    const result = render(<TokenAccess />);
    expect(screen.getByText("Created")).toBeInTheDocument();
    expect(screen.getByText("03:48 PM Feb 22nd, 2024")).toBeInTheDocument();

    const deleteButton = result.container.querySelector("#delete-apikey-btn");
    expect(deleteButton).toBeInTheDocument();
    await user.click(deleteButton);
    const deletionConfirmButton = screen.getByRole("button", { name: /Yes/i });
    expect(deletionConfirmButton).toBeInTheDocument();
    await user.click(deletionConfirmButton);
    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(`${APIACCESS_BASE_URI}`);
    });
    await waitFor(() => {
      expect(useAxios).toHaveBeenCalledWith(
        { url: `${APIACCESS_BASE_URI}` },
        { useCache: false },
      );
    });
    result.rerender(<TokenAccess />);
    expect(screen.getByText("06:48 PM Feb 22nd, 2024")).toBeInTheDocument();
  });

  test("create token", async () => {
    useAxios
      .mockImplementation(() => [
        {
          data: {
            key: "987654321",
            created: "2024-02-22T18:48:18.257944",
          },
          loading: false,
          error: "",
        },
      ])
      .mockImplementationOnce(() => [
        {
          data: undefined,
          loading: false,
          error: {
            response: { status: 404 },
            errors: { detail: "Not found." },
          },
        },
      ]);

    const user = userEvent.setup();

    const result = render(<TokenAccess />);

    expect(screen.getByText("No active API key")).toBeInTheDocument();
    const createButton = result.container.querySelector("#create-apikey-btn");
    expect(createButton).toBeInTheDocument();
    await user.click(createButton);
    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${APIACCESS_BASE_URI}`);
    });

    result.rerender(<TokenAccess />);
    expect(screen.getByText("Created")).toBeInTheDocument();
    expect(screen.getByText("06:48 PM Feb 22nd, 2024")).toBeInTheDocument();
  });
});
