import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";

import {
  JOB_DETAIL_RE,
  INVESTIGATION_DETAIL_RE,
  QuickActions,
} from "../../../src/components/chat/QuickActions";

// window.location is non-writable in JSDOM — delete and replace to mock pathname.
function mockLocation(pathname) {
  delete window.location;
  window.location = new URL(`https://intelowl.test${pathname}`);
}

function restoreLocation() {
  delete window.location;
  window.location = new URL("https://intelowl.test/dashboard");
}

describe("QuickActions", () => {
  afterEach(() => {
    restoreLocation();
  });

  it("shows job-specific chips on a job detail page", () => {
    mockLocation("/jobs/42");
    render(<QuickActions onSend={jest.fn()} />);

    expect(screen.getByText("Summarize this job")).toBeInTheDocument();
    expect(screen.getByText("Which plugins ran?")).toBeInTheDocument();
    expect(screen.getByText("Show job details")).toBeInTheDocument();
    expect(screen.getByText("Evaluate results")).toBeInTheDocument();
    // generic chips must not appear
    expect(screen.queryByText("Show my recent jobs")).not.toBeInTheDocument();
  });

  it("shows job-specific chips on a job sub-page", () => {
    mockLocation("/jobs/42/visualizer/DNS");
    render(<QuickActions onSend={jest.fn()} />);
    expect(screen.getByText("Summarize this job")).toBeInTheDocument();
  });

  it("shows investigation-specific chips on an investigation page", () => {
    mockLocation("/investigation/7");
    render(<QuickActions onSend={jest.fn()} />);

    expect(
      screen.getByText("Summarize this investigation"),
    ).toBeInTheDocument();
    expect(screen.getByText("Show investigation tree")).toBeInTheDocument();
    expect(screen.getByText("Analyze this investigation")).toBeInTheDocument();
  });

  it("shows generic chips on non-entity pages", () => {
    mockLocation("/dashboard");
    render(<QuickActions onSend={jest.fn()} />);

    expect(screen.getByText("Show my recent jobs")).toBeInTheDocument();
    expect(screen.getByText("List my investigations")).toBeInTheDocument();
  });

  it("falls back to generic chips for non-numeric job id", () => {
    mockLocation("/jobs/abc");
    render(<QuickActions onSend={jest.fn()} />);
    expect(screen.getByText("Show my recent jobs")).toBeInTheDocument();
  });

  it("calls onSend with resolved id on chip click", async () => {
    mockLocation("/jobs/42");
    const onSend = jest.fn();
    render(<QuickActions onSend={onSend} />);

    await userEvent.click(screen.getByText("Summarize this job"));
    expect(onSend).toHaveBeenCalledWith("Summarize job #42");
  });

  it("calls onSend with resolved id on Evaluate results click", async () => {
    mockLocation("/jobs/42");
    const onSend = jest.fn();
    render(<QuickActions onSend={onSend} />);

    await userEvent.click(screen.getByText("Evaluate results"));
    expect(onSend).toHaveBeenCalledWith("Evaluate the results of job #42");
  });

  it("calls onSend with the raw message on generic pages", async () => {
    mockLocation("/dashboard");
    const onSend = jest.fn();
    render(<QuickActions onSend={onSend} />);

    await userEvent.click(screen.getByText("Show my recent jobs"));
    expect(onSend).toHaveBeenCalledWith("Show my recent jobs");
  });

  it("does not call onSend when disabled", async () => {
    mockLocation("/jobs/42");
    const onSend = jest.fn();
    render(<QuickActions onSend={onSend} disabled />);

    await userEvent.click(screen.getByText("Summarize this job"));
    expect(onSend).not.toHaveBeenCalled();
  });

  describe("coupling: regexes match frontend Routes.jsx paths", () => {
    // Mirror of the backend test_context.py coupling test.
    // When Routes.jsx paths change, these regexes must change in lockstep
    // with context.py — this test catches silent frontend-only drift.

    it("JOB_DETAIL_RE matches all job detail routes", () => {
      [
        "/jobs/42",
        "/jobs/42/visualizer",
        "/jobs/42/visualizer/DNS",
        "/jobs/42/comments",
      ].forEach((path) => {
        expect(JOB_DETAIL_RE.test(path)).toBe(true);
      });
    });

    it("INVESTIGATION_DETAIL_RE matches investigation detail routes", () => {
      ["/investigation/7", "/investigation/7/something"].forEach((path) => {
        expect(INVESTIGATION_DETAIL_RE.test(path)).toBe(true);
      });
    });

    it("neither regex matches non-entity paths", () => {
      [
        "/dashboard",
        "/plugins/analyzers",
        "/history/jobs",
        "/artifacts/3",
      ].forEach((path) => {
        expect(JOB_DETAIL_RE.test(path)).toBe(false);
        expect(INVESTIGATION_DETAIL_RE.test(path)).toBe(false);
      });
    });
  });
});
