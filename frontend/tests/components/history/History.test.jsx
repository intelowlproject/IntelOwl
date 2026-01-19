import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import History from "../../../src/components/history/History";
import { INVESTIGATION_BASE_URI } from "../../../src/constants/apiURLs";

jest.mock("axios");
// mock HistoryTable components
jest.mock("../../../src/components/history/HistoryTable", () => ({
  HistoryTable: jest.fn((props) => <div {...props} />),
}));

describe("test History component", () => {
  test("history page", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter
        initialEntries={[
          "/history/jobs?received_request_time__gte=2025-12-08T15%3A28%3A05.317Z&received_request_time__lte=2025-12-15T15%3A28%3A05.317Z&ordering=-received_request_time",
        ]}
      >
        <History />
      </MemoryRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");

    // jobs tab selected
    const jobsButton = screen.getByText("Jobs");
    expect(jobsButton).toBeInTheDocument();
    expect(jobsButton.closest("a").className).toContain("active"); // selected
    expect(jobsButton.closest("a").href).toContain("/history/jobs");
    expect(jobsButton.closest("a").href).toContain(
      "received_request_time__gte",
    );
    expect(jobsButton.closest("a").href).toContain(
      "received_request_time__lte",
    );

    const createJobButton = screen.getByRole("button", { name: /Create job/i });
    expect(createJobButton).toBeInTheDocument();

    const investigationButton = screen.getByText("Investigations");
    expect(investigationButton).toBeInTheDocument();
    expect(investigationButton.closest("a").className).not.toContain("active"); // not selected
    expect(investigationButton.closest("a").href).toContain(
      "/history/investigations",
    );
    expect(investigationButton.closest("a").href).toContain("start_time__gte");
    expect(investigationButton.closest("a").href).toContain("start_time__lte");

    const artifactsButton = screen.getByText("Artifacts evaluations");
    expect(artifactsButton).toBeInTheDocument();
    expect(artifactsButton.closest("a").className).not.toContain("active"); // not selected
    expect(artifactsButton.closest("a").href).toContain("/history/user-events");
    expect(artifactsButton.closest("a").href).toContain("event_date__gte");
    expect(artifactsButton.closest("a").href).toContain("event_date__lte");

    const ipWildcardButton = screen.getByText("Ip wildcard evaluations");
    expect(ipWildcardButton).toBeInTheDocument();
    expect(ipWildcardButton.closest("a").className).not.toContain("active"); // not selected
    expect(ipWildcardButton.closest("a").href).toContain(
      "/history/user-ip-wildcard-events",
    );
    expect(ipWildcardButton.closest("a").href).toContain("event_date__gte");
    expect(ipWildcardButton.closest("a").href).toContain("event_date__lte");

    const domainWildcardButton = screen.getByText(
      "Domain wildcard evaluations",
    );
    expect(domainWildcardButton).toBeInTheDocument();
    expect(domainWildcardButton.closest("a").className).not.toContain("active"); // not selected
    expect(domainWildcardButton.closest("a").href).toContain(
      "/history/user-domain-wildcard-events",
    );
    expect(domainWildcardButton.closest("a").href).toContain("event_date__gte");
    expect(domainWildcardButton.closest("a").href).toContain("event_date__lte");

    // investigation tab selected
    await user.click(investigationButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(investigationButton.closest("a").className).toContain("active"); // selected
      expect(artifactsButton.closest("a").className).not.toContain("active"); // not selected
      expect(ipWildcardButton.closest("a").className).not.toContain("active"); // not selected
      expect(domainWildcardButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
      const createInvestigationButton = screen.getByRole("button", {
        name: /Create investigation/i,
      });
      expect(createInvestigationButton).toBeInTheDocument();
    });

    // user event - analyzables tab selected
    await user.click(artifactsButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(investigationButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
      expect(artifactsButton.closest("a").className).toContain("active"); // selected
      const createEvaluationButton = screen.getByRole("button", {
        name: /New evaluation/i,
      });
      expect(createEvaluationButton).toBeInTheDocument();
      expect(ipWildcardButton.closest("a").className).not.toContain("active"); // not selected
      expect(domainWildcardButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
    });

    // user event - ip wildcard tab selected
    await user.click(ipWildcardButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(investigationButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
      expect(artifactsButton.closest("a").className).not.toContain("active"); // not selected
      expect(ipWildcardButton.closest("a").className).toContain("active"); // selected
      const createEvaluationButton = screen.getByRole("button", {
        name: /New evaluation/i,
      });
      expect(createEvaluationButton).toBeInTheDocument();
      expect(domainWildcardButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
    });

    // user event - domain wildcard tab selected
    await user.click(domainWildcardButton);
    await waitFor(() => {
      expect(jobsButton.closest("a").className).not.toContain("active"); // not selected
      expect(investigationButton.closest("a").className).not.toContain(
        "active",
      ); // not selected
      expect(artifactsButton.closest("a").className).not.toContain("active"); // not selected
      expect(ipWildcardButton.closest("a").className).not.toContain("active"); // not selected
      expect(domainWildcardButton.closest("a").className).toContain("active"); // selected
      const createEvaluationButton = screen.getByRole("button", {
        name: /New evaluation/i,
      });
      expect(createEvaluationButton).toBeInTheDocument();
    });
  });

  test("create new investigation", async () => {
    axios.post.mockImplementation(() => Promise.resolve({ data: {} }));
    const user = userEvent.setup();
    render(
      <MemoryRouter
        initialEntries={[
          "/history/jobs?received_request_time__gte=2025-12-08T15%3A28%3A05.317Z&received_request_time__lte=2025-12-15T15%3A28%3A05.317Z&ordering=-received_request_time",
        ]}
      >
        <History />
      </MemoryRouter>,
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
