import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DownloadVisualizer } from "../../../../../../src/components/common/visualizer/elements/download";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("DownalodVisualizer component", () => {
  test("required-only params", async () => {
    const { container } = render(
      <DownloadVisualizer
        size="col-1"
        value="test-required.txt"
        mimetype="plain/text"
        payload="test only required params"
        id="test-id"
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText("test-required.txt");
    expect(innerPartComponent).toBeInTheDocument();
    // check no link
    expect(innerPartComponent.closest("div").style).not.toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check size and alignment
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-1  p-0 m-1 d-flex align-items-center text-center justify-content-center ",
    );
    // check tooltip
    const user = userEvent.setup();
    await user.hover(innerPartComponent);
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
    });
  });

  test("all params", async () => {
    const { container } = render(
      <DownloadVisualizer
        size="col-2"
        alignment="end"
        value="test-all.txt"
        mimetype="plain/text"
        payload="test all params"
        id="test-id"
        copyText="test-all.txt"
        description="this is a test file"
        addMetadataInDescription
        isChild
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText("test-all.txt");
    expect(innerPartComponent).toBeInTheDocument();
    // check optional elements
    expect(idElement.className).toBe(
      "col-2 small p-0 m-1 d-flex align-items-center text-end justify-content-end ",
    );
    // check tooltip
    const user = userEvent.setup();
    await user.hover(innerPartComponent);
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
    });
  });

  test("test disable", async () => {
    // it's a special case because change the style, but also the interactions

    const { container } = render(
      <DownloadVisualizer
        size="col-2"
        alignment="end"
        value="test-disabled.txt"
        mimetype="plain/text"
        payload="test all params"
        id="test-id"
        copyText="test-disabled.txt"
        description="this is a test file"
        addMetadataInDescription
        isChild
        disable
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText("test-disabled.txt");
    expect(innerPartComponent).toBeInTheDocument();
    // check optional elements
    expect(idElement.className).toBe(
      "col-2 small p-0 m-1 d-flex align-items-center text-end justify-content-end opacity-25",
    );
  });
});
