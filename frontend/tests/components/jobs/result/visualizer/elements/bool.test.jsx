import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { getIcon } from "../../../../../../src/components/common/icon/icons";
import { BooleanVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/bool";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("BooleanVisualizer component", () => {
  test("required-only params", async () => {
    const { container } = render(
      <BooleanVisualizer
        id="test-id"
        size="col-1"
        value="test bool (required-only params)"
      />,
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText(
      "test bool (required-only params)",
    );
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).not.toContain("fst-italic");
    // check icon
    expect(screen.queryByRole("img")).toBeNull();
    // check no link
    expect(innerPartComponent.closest("div").style).not.toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-1");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-danger");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
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
      <BooleanVisualizer
        id="test-id"
        size="col-2"
        value="test bool (all params)"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        activeColor="success"
        link="https://google.com"
        italic
        description="description"
      />,
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test bool (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).toBe("fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("div").style).toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-2");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-success");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    /// check tooltip
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
      <BooleanVisualizer
        id="test-id"
        size="col-2"
        value="test bool (disable)"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        activeColor="success"
        link="https://google.com"
        italic
        disable
        description=""
      />,
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test bool (disable)");
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).toBe("fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check no link
    expect(innerPartComponent.closest("div").style).not.toHaveProperty(
      "text-decoration",
      "underline dotted",
    );
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-2");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-gray");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });
});
