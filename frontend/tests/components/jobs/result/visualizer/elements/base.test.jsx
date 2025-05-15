import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BaseVisualizer } from "../../../../../../src/components/common/visualizer/elements/base";
import { getIcon } from "../../../../../../src/components/common/icon/icons";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("BaseVisualizer component", () => {
  test("required-only params", async () => {
    const { container } = render(
      <BaseVisualizer
        size="col-1"
        value="test base (required-only params)"
        id="test-id"
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText(
      "test base (required-only params)",
    );
    expect(innerPartComponent).toBeInTheDocument();
    // check no color, bold and italic
    expect(innerPartComponent.className).toBe("   ");
    // check no icon
    expect(screen.queryByRole("img")).toBeNull();
    // check no link
    expect(innerPartComponent.closest("div").style).not.toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check size and alignment
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-1  p-0 m-1 d-flex align-items-center text-center justify-content-center  ",
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
      <BaseVisualizer
        id="test-id"
        size="col-2"
        value="test base (all params)"
        alignment="start"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        color="success"
        link="https://google.com"
        bold
        italic
        copyText="test base (copyText)"
        isChild
        description="description test all params"
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe(
      "small success fw-bold fst-italic",
    );
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("div").style).toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check optional elements (like bold, italic...)
    expect(idElement.className).toBe(
      "col-2 small p-0 m-1 d-flex align-items-center text-start justify-content-start  success",
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
      <BaseVisualizer
        id="test-id"
        size="col-2"
        value="test base (disable)"
        alignment="start"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        color="success"
        link="https://google.com"
        bold
        italic
        disable
        copyText="test base (copyText)"
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (disable)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe(" success fw-bold fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check no link
    expect(innerPartComponent.closest("div").style).not.toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check optional elements (like bold, italic...)
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-2  p-0 m-1 d-flex align-items-center text-start justify-content-start opacity-25 success",
    );
  });
});
