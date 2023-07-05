import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VisualizerTooltip } from "../../../../../src/components/jobs/result/visualizer/VisualizerTooltip";

describe("VisualizerTooltip component", () => {
  test("copy button - link button disabled", async () => {
    render(
      <>
        <div id="test-id-tooltip">Test</div>
        <VisualizerTooltip
          idElement="test-id-tooltip"
          copyText="test copyText"
          link=""
          description=""
        />
      </>
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip"
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByRole("button", { name: "Link" });
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).toContain("disabled");
    });
  });

  test("copy button - link button enabled", async () => {
    render(
      <>
        <div id="test-id-tooltip">Test</div>
        <VisualizerTooltip
          idElement="test-id-tooltip"
          copyText="test copyText"
          link="https://google.com/"
          description=""
        />
      </>
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip"
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByRole("button", { name: "Link" });
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).not.toContain("disabled");
      expect(screen.getByRole("link").href).toBe("https://google.com/");
    });
  });

  test("buttons and description", async () => {
    render(
      <>
        <div id="test-id-tooltip">Test</div>
        <VisualizerTooltip
          idElement="test-id-tooltip"
          copyText="test copyText"
          link="https://google.com/"
          description="description tooltip"
        />
      </>
    );
    const user = userEvent.setup();
    await user.hover(screen.getByText("Test"));
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
      // check copy button
      const copyButton = tooltipElement.querySelector(
        "#copyBtn-test-id-tooltip"
      );
      expect(copyButton).toBeInTheDocument();
      // check link button
      const linkButton = screen.getByRole("button", { name: "Link" });
      expect(linkButton).toBeInTheDocument();
      expect(linkButton.className).not.toContain("disabled");
      expect(screen.getByRole("link").href).toBe("https://google.com/");
      // check description
      expect(screen.getByText("description tooltip")).toBeInTheDocument();
    });
  });
});
