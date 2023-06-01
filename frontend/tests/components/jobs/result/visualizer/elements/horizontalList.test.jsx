import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { HorizontalListVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/horizontalList";
import { BaseVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/base";
import { BooleanVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/bool";
import { TitleVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/title";
import { VerticalListVisualizer } from "../../../../../../src/components/jobs/result/visualizer/elements/verticalList";

describe("HorizontalListVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <HorizontalListVisualizer
        values={[
          <BaseVisualizer value="base element" />,
          <BooleanVisualizer value="bool element" />,
          <TitleVisualizer
            title={<BaseVisualizer value="title element - title" />}
            value={<BaseVisualizer value="title element - value" />}
          />,
          <VerticalListVisualizer
            name={<BaseVisualizer value="vertical list element - name" />}
            values={[
              <BaseVisualizer value="vertical list element - first element" />,
            ]}
          />,
        ]}
      />
    );

    screen.debug();

    // check alignment
    expect(container.firstChild.className).toContain("justify-content-around");
    expect(screen.getByText("base element")).toBeInTheDocument();
    expect(screen.getByText("bool element")).toBeInTheDocument();
    expect(screen.getByText("title element - title")).toBeInTheDocument();
    expect(
      screen.getByText("vertical list element - name")
    ).toBeInTheDocument();
  });

  test("all params", () => {
    const { container } = render(
      <HorizontalListVisualizer
        values={[
          <BaseVisualizer value="base element" />,
          <BooleanVisualizer value="bool element" />,
          <TitleVisualizer
            title={<BaseVisualizer value="title element - title" />}
            value={<BaseVisualizer value="title element - value" />}
          />,
          <VerticalListVisualizer
            name={<BaseVisualizer value="vertical list element - name" />}
            values={[
              <BaseVisualizer value="vertical list element - first element" />,
            ]}
          />,
        ]}
        alignment="between"
      />
    );

    screen.debug();

    // check alignment
    expect(container.firstChild.className).toContain("justify-content-between");
    expect(screen.getByText("base element")).toBeInTheDocument();
    expect(screen.getByText("bool element")).toBeInTheDocument();
    expect(screen.getByText("title element - title")).toBeInTheDocument();
    expect(
      screen.getByText("vertical list element - name")
    ).toBeInTheDocument();
  });
});
