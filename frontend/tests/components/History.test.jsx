import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import History from "../../src/components/History";
import { INVESTIGATION_BASE_URI } from "../../src/constants/apiURLs";

jest.mock("axios");
// mock JobsTable and InvestigationsTable components
jest.mock("../../src/components/jobs/table/JobsTable", () =>
  jest.fn((props) => <div {...props} />),
);
jest.mock("../../src/components/investigations/table/InvestigationsTable", () =>
  jest.fn((props) => <div {...props} />),
);

describe("test History component", () => {
  test("history page", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <History />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");

    // jobs tab selected
    const jobsButton = screen.getByText("Jobs");
    expect(jobsButton).toBeInTheDocument();
    expect(jobsButton.closest("a").className).toContain("active"); // selected

    const createJobButton = screen.getByRole("button", { name: /Create job/i });
    expect(createJobButton).toBeInTheDocument();

    const investigationButton = screen.getByText("Investigations");
    expect(investigationButton).toBeInTheDocument();
    expect(investigationButton.closest("a").className).not.toContain("active"); // not selected

    // investigation tab selected
    await user.click(investigationButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(investigationButton.closest("a").className).toContain("active"); // selected
      const createInvestigationButton = screen.getByRole("button", {
        name: /Create investigation/i,
      });
      expect(createInvestigationButton).toBeInTheDocument();
    });
  });

  test("create new investigation", async () => {
    axios.post.mockImplementation(() => Promise.resolve({ data: {} }));
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <History />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");

    // investigation tab selected
    const investigationButton = screen.getByText("Investigations");
    expect(investigationButton).toBeInTheDocument();
    await user.click(investigationButton);
    expect(investigationButton.closest("a").className).toContain("active"); // selected

    const createInvestigationButton = screen.getByRole("button", {
      name: /Create investigation/i,
    });
    expect(createInvestigationButton).toBeInTheDocument();

    await user.click(createInvestigationButton);
    await waitFor(() => {
      // create new investigation
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post).toHaveBeenCalledWith(INVESTIGATION_BASE_URI, {
        name: "Custom investigation",
        description: "",
        for_organization: true,
      });
    });
  });
});
