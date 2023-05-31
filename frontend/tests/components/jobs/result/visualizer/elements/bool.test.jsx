import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { getIcon } from "../../../../../../src/components/jobs/result/visualizer/icons";
import { BooleanVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/bool";

describe("BooleanVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <BooleanVisualizer
        size="col-1"
        value="test bool (required-only params)"
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText(
      "test bool (required-only params)"
    );
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).not.toContain("fst-italic");
    // check icon
    expect(screen.queryByRole("img")).toBeNull();
    // check link is available
    expect(innerPartComponent.closest("a")).toBeNull();
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-1");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-danger");
  });

  test("all params", () => {
    const { container } = render(
      <BooleanVisualizer
        size="col-2"
        value="test bool (all params)"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        activeColor="success"
        link="https://google.com"
        italic
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test bool (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).toBe("fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a").href).toBe("https://google.com/");
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-2");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-success");
  });

  test("test disable", () => {
    // it's a special case because change the style, but also the interactions

    const { container } = render(
      <BooleanVisualizer
        size="col-2"
        value="test bool (all params)"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        activeColor="success"
        link="https://google.com"
        italic
        disable
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test bool (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check italic
    expect(innerPartComponent.className).toBe("fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a")).toBeNull();
    // check size
    const sizeComponent = container.firstChild;
    expect(sizeComponent.className).toBe("col-2");
    // check color
    const badgeElement = sizeComponent.firstChild;
    expect(badgeElement.className).toContain("bg-gray");
  });
});
