import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { TitleVisualizer } from "../../../../../../src/components/common/visualizer/elements/title";
import { BaseVisualizer } from "../../../../../../src/components/common/visualizer/elements/base";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("TitleVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <TitleVisualizer
        id="test-id"
        size="col-2"
        title={
          <BaseVisualizer
            size="auto"
            value="title (required-only params)"
            id="test-id-title"
          />
        }
        value={
          <BaseVisualizer
            size="auto"
            value="value (required-only params)"
            id="test-id-value"
          />
        }
      />,
    );

    // check title
    expect(
      screen.getByText("title (required-only params)"),
    ).toBeInTheDocument();
    // check value
    expect(
      screen.getByText("value (required-only params)"),
    ).toBeInTheDocument();
    // check size and alignment
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.className).toContain("align-items-center");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });

  test("all params", () => {
    const { container } = render(
      <TitleVisualizer
        id="test-id"
        size="col-2"
        title={
          <BaseVisualizer
            size="auto"
            value="title (all params)"
            id="test-id-title"
          />
        }
        value={
          <BaseVisualizer
            size="auto"
            value="value (all params)"
            id="test-id-value"
          />
        }
        alignment="start"
      />,
    );

    // check title
    expect(screen.getByText("title (all params)")).toBeInTheDocument();
    // check value
    expect(screen.getByText("value (all params)")).toBeInTheDocument();
    // check size and alignment
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.className).toContain("align-items-start");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });
});
