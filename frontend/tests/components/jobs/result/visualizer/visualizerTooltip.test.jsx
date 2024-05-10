import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { VisualizerTooltip } from "../../../../../src/components/jobs/result/visualizer/VisualizerTooltip";

describe("VisualizerTooltip component", () => {
  test("copy button - link button disabled", async () => {
    render(
      <MemoryRouter initialEntries={["/jobs/123/visualizer/DNS"]}>
        <>
          <div id="test-id-tooltip">Test</div>
          <VisualizerTooltip
            idElement="test-id-tooltip"
            copyText="test copyText"
            link=""
            description=""
          />
        </>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip",
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByText("Link");
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).toContain("disabled");
    });
  });

  test("copy button - link button enabled", async () => {
    render(
      <MemoryRouter initialEntries={["/jobs/123/visualizer/DNS"]}>
        <>
          <div id="test-id-tooltip">Test</div>
          <VisualizerTooltip
            idElement="test-id-tooltip"
            copyText="test copyText"
            link="https://google.com/"
            description=""
          />
        </>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip",
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByText("Link");
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).not.toContain("disabled");
      expect(screen.getByRole("link").href).toBe("https://google.com/");
    });
  });

  test("buttons and description", async () => {
    render(
      <MemoryRouter initialEntries={["/jobs/123/visualizer/DNS"]}>
        <>
          <div id="test-id-tooltip">Test</div>
          <VisualizerTooltip
            idElement="test-id-tooltip"
            copyText="google.com"
            link="https://google.com/"
            description="description tooltip"
          />
        </>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip",
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByText("Link");
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).not.toContain("disabled");
      expect(linkButton.href).toBe("https://google.com/");
      // check pivot button
      const pivotButton = screen.getByText("Pivot");
      expect(pivotButton).toBeInTheDocument();
      expect(pivotButton.href).toContain(
        "/scan?parent=123&observable=google.com",
      );
      // check description
      expect(screen.getByText("description tooltip")).toBeInTheDocument();
    });
  });
});
