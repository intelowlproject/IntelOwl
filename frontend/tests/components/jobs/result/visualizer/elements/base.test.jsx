import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BaseVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/base";
import { getIcon } from "../../../../../../src/components/jobs/result/visualizer/icons";

describe("BaseVisualizer component", () => {
  test("required-only params", () => {
    render(
      <BaseVisualizer size="col-1" value="test base (required-only params)" />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText(
      "test base (required-only params)"
    );
    expect(innerPartComponent).toBeInTheDocument();
    // check no color, bold and italic
    expect(innerPartComponent.className).toBe("  ");
    // check no icon
    expect(screen.queryByRole("img")).toBeNull();
    // check no link
    expect(innerPartComponent.closest("a")).toBeNull();
    // check size and alignment
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-1 small d-flex align-items-center text-center justify-content-center  "
    );
  });

  test("all params", () => {
    render(
      <BaseVisualizer
        size="col-2"
        value="test base (all params)"
        alignment="start"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        color="success"
        link="https://google.com"
        bold
        italic
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe("success fw-bold fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a").href).toBe("https://google.com/");
    // check optional elements (like bold, italic...)
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-2 small d-flex align-items-center text-start justify-content-start  success"
    );
  });

  test("test disable", () => {
    // it's a special case because change the style, but also the interactions

    render(
      <BaseVisualizer
        size="col-2"
        value="test base (all params)"
        alignment="start"
        // this wrapper with div is required to access to the element in the assertions
        icon={<div role="img">{getIcon("like")}</div>}
        color="success"
        link="https://google.com"
        bold
        italic
        disable
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe("success fw-bold fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a")).toBeNull();
    // check optional elements (like bold, italic...)
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-2 small d-flex align-items-center text-start justify-content-start opacity-25 success"
    );
  });
});
