import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BaseVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/base";
import { VerticalListVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/verticalList";
import { HorizontalListVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/horizontalList";

describe("VerticalListVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <VerticalListVisualizer
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (required-only params)"
            color="warning"
          />
        }
        values={[
          <BaseVisualizer size="auto" value="first line - single element" />,
          <HorizontalListVisualizer
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
              />,
            ]}
          />,
        ]}
      />
    );

    // check title
    expect(
      screen.getByText("title (required-only params)")
    ).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element")
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    // check button
    const dropdownButton = screen.getByRole("button");
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-warning");
  });

  test("all params", () => {
    const { container } = render(
      <VerticalListVisualizer
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (all params)"
            color="success"
          />
        }
        values={[
          <BaseVisualizer size="auto" value="first line - single element" />,
          <HorizontalListVisualizer
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
              />,
            ]}
          />,
        ]}
        alignment="start"
        startOpen
      />
    );

    // check title
    expect(screen.getByText("title (all params)")).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element")
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    // check button
    const dropdownButton = screen.getByRole("button");
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-success");
  });

  test("all params - disable", () => {
    const { container } = render(
      <VerticalListVisualizer
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (all params)"
            color="success"
          />
        }
        values={[
          <BaseVisualizer size="auto" value="first line - single element" />,
          <HorizontalListVisualizer
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
              />,
            ]}
          />,
        ]}
        alignment="start"
        startOpen
        disable
      />
    );

    // check title
    expect(screen.getByText("title (all params)")).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element")
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    expect(mainComponent.firstChild.className).toContain("opacity-50");
    // check button
    const dropdownButton = screen.getByRole("button");
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-success");
  });
});
