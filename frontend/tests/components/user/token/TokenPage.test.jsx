import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";

import useAxios from "axios-hooks";

import TokenPage from "../../../../src/components/user/token/TokenPage";

jest.mock("axios-hooks");

useAxios.mockReturnValue([
  {
    data: {
      key: "123456789",
      created: "2024-02-22T15:48:18.257944",
    },
  },
]);

describe("test TokenPage", () => {
  test("render", () => {
    render(<TokenPage />);
    expect(screen.getByText("API Access")).toBeInTheDocument();
    expect(screen.getByText("Created")).toBeInTheDocument();
    expect(screen.getByText("03:48 PM Feb 22nd, 2024")).toBeInTheDocument();
  });
});
