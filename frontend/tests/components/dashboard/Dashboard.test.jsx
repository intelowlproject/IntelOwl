import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import Dashboard from "../../../src/components/dashboard/Dashboard";

describe("test Dashboard component", () => {
  test("Dashboard page", async () => {
    render(<Dashboard />);

    // header
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    // time picker
    expect(screen.getByText("6h")).toBeInTheDocument();
    expect(screen.getByText("24h")).toBeInTheDocument();
    expect(screen.getByText("7d")).toBeInTheDocument();
    // charts
    expect(screen.getByText("Job: Status")).toBeInTheDocument();
    expect(screen.getByText("Job: Type")).toBeInTheDocument();
    expect(
      screen.getByText("Job: Observable Classification"),
    ).toBeInTheDocument();
    expect(screen.getByText("Job: File Mimetype")).toBeInTheDocument();
    expect(screen.getByText("Job: Top 5 Playbooks")).toBeInTheDocument();
    expect(screen.getByText("Job: Top 5 Users")).toBeInTheDocument();
    expect(screen.getByText("Job: Top 5 TLP")).toBeInTheDocument();
  });
});
