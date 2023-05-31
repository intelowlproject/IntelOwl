import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { TitleVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/title";
import { BaseVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/base";

describe("TitleVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <TitleVisualizer
        size="col-2"
        title={
          <BaseVisualizer size="auto" value="title (required-only params)" />
        }
        value={
          <BaseVisualizer size="auto" value="value (required-only params)" />
        }
      />
    );

    // check title
    expect(
      screen.getByText("title (required-only params)")
    ).toBeInTheDocument();
    // check value
    expect(
      screen.getByText("value (required-only params)")
    ).toBeInTheDocument();
    // check size and alignment
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.className).toContain("align-items-center");
  });

  test("all params", () => {
    const { container } = render(
      <TitleVisualizer
        size="col-2"
        title={<BaseVisualizer size="auto" value="title (all params)" />}
        value={<BaseVisualizer size="auto" value="value (all params)" />}
        alignment="start"
      />
    );

    // check title
    expect(screen.getByText("title (all params)")).toBeInTheDocument();
    // check value
    expect(screen.getByText("value (all params)")).toBeInTheDocument();
    // check size and alignment
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.className).toContain("align-items-start");
  });
});
