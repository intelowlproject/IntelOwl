import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import History from "../../src/components/History";
import { ANALYSIS_BASE_URI } from "../../src/constants/apiURLs";

jest.mock("axios");
// mock JobsTable and AnalysisTable components
jest.mock("../../src/components/jobs/table/JobsTable", () =>
  jest.fn((props) => <div {...props} />),
);
jest.mock("../../src/components/analysis/table/AnalysisTable", () =>
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

    const analysisButton = screen.getByText("Analysis");
    expect(analysisButton).toBeInTheDocument();
    expect(analysisButton.closest("a").className).not.toContain("active"); // not selected

    // analysis tab selected
    await user.click(analysisButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(analysisButton.closest("a").className).toContain("active"); // selected
      const createAnalysisButton = screen.getByRole("button", {
        name: /Create analysis/i,
      });
      expect(createAnalysisButton).toBeInTheDocument();
    });
  });

  test("create new analysis", async () => {
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

    // analysis tab selected
    const analysisButton = screen.getByText("Analysis");
    expect(analysisButton).toBeInTheDocument();
    await user.click(analysisButton);
    expect(analysisButton.closest("a").className).toContain("active"); // selected

    const createAnalysisButton = screen.getByRole("button", {
      name: /Create analysis/i,
    });
    expect(createAnalysisButton).toBeInTheDocument();

    await user.click(createAnalysisButton);
    await waitFor(() => {
      // create new analysis
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post).toHaveBeenCalledWith(ANALYSIS_BASE_URI, {
        name: "Custom analysis",
        description: "",
      });
    });
  });
});
