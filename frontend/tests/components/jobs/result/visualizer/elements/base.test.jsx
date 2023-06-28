import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BaseVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/base";
import { getIcon } from "../../../../../../src/components/jobs/result/visualizer/icons";

describe("BaseVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <BaseVisualizer
        size="col-1"
        value="test base (required-only params)"
        id="test-id"
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText(
      "test base (required-only params)"
    );
    expect(innerPartComponent).toBeInTheDocument();
    // check no color, bold and italic
    expect(innerPartComponent.className).toBe("   ");
    // check no icon
    expect(screen.queryByRole("img")).toBeNull();
    // check no link
    expect(innerPartComponent.closest("a")).toBeNull();
    // check size and alignment
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-1  d-flex align-items-center text-center justify-content-center  "
    );
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // check copyButton
    const copyButton = screen.getByRole("button", {
      name: "test base (required-only params)",
    });
    expect(copyButton).toBeInTheDocument();
  });

  test("all params", () => {
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
        copyText="test base (copyText)"
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (all params)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe(
      "small success fw-bold fst-italic"
    );
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a").href).toBe("https://google.com/");
    // check optional elements (like bold, italic...)
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-2 small d-flex align-items-center text-start justify-content-start  success"
    );
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // check copyButton
    const copyButton = screen.getByRole("button", {
      name: "test base (all params)",
    });
    expect(copyButton).toBeInTheDocument();
  });

  test("test disable", () => {
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
      />
    );

    // chec text (inner span)
    const innerPartComponent = screen.getByText("test base (disable)");
    expect(innerPartComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(innerPartComponent.className).toBe(" success fw-bold fst-italic");
    // check icon
    expect(screen.getByRole("img")).toBeInTheDocument();
    // check link is available
    expect(innerPartComponent.closest("a")).toBeNull();
    // check optional elements (like bold, italic...)
    const outerPartComponent = innerPartComponent.closest("div");
    expect(outerPartComponent.className).toBe(
      "col-2  d-flex align-items-center text-start justify-content-start opacity-25 success"
    );
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // check copyButton
    const copyButton = screen.getByRole("button", {
      name: "test base (disable)",
    });
    expect(copyButton).toBeInTheDocument();
  });

  test("test no copyButton", () => {
    const { container } = render(
      <BaseVisualizer
        id="test-id-title"
        size="col-2"
        value="test no copyButton"
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
    const innerPartComponent = screen.getByText("test no copyButton");
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
    // check id
    const idElement = container.querySelector("#test-id-title");
    expect(idElement).toBeInTheDocument();
    // check copyButton
    const copyButton = container.querySelector("#copyBtn-test-id-title");
    expect(copyButton).not.toBeInTheDocument();
  });
});
