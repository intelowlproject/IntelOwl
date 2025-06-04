import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { HorizontalListVisualizer } from "../../../../../../src/components/common/visualizer/elements/horizontalList";
import { BaseVisualizer } from "../../../../../../src/components/common/visualizer/elements/base";
import { BooleanVisualizer } from "../../../../../../src/components/common/visualizer/elements/bool";
import { TitleVisualizer } from "../../../../../../src/components/common/visualizer/elements/title";
import { VerticalListVisualizer } from "../../../../../../src/components/common/visualizer/elements/verticalList";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("HorizontalListVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <HorizontalListVisualizer
        id="test-id"
        values={[
          <BaseVisualizer value="base element" id="test-id-base" />,
          <BooleanVisualizer value="bool element" id="test-id-bool" />,
          <TitleVisualizer
            title={
              <BaseVisualizer
                value="title element - title"
                id="test-id-title"
              />
            }
            value={
              <BaseVisualizer
                value="title element - value"
                id="test-id-value"
              />
            }
          />,
          <VerticalListVisualizer
            name={
              <BaseVisualizer
                value="vertical list element - name"
                id="test-id-vlist"
              />
            }
            values={[
              <BaseVisualizer
                value="vertical list element - first element"
                id="test-id-value"
              />,
            ]}
          />,
        ]}
      />,
    );

    screen.debug();

    // check alignment
    expect(container.firstChild.className).toContain("justify-content-around");
    expect(screen.getByText("base element")).toBeInTheDocument();
    expect(screen.getByText("bool element")).toBeInTheDocument();
    expect(screen.getByText("title element - title")).toBeInTheDocument();
    expect(
      screen.getByText("vertical list element - name"),
    ).toBeInTheDocument();
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });

  test("all params", () => {
    const { container } = render(
      <HorizontalListVisualizer
        id="test-id"
        values={[
          <BaseVisualizer value="base element" id="test-id-base" />,
          <BooleanVisualizer value="bool element" id="test-id-bool" />,
          <TitleVisualizer
            title={
              <BaseVisualizer
                value="title element - title"
                id="test-id-title"
              />
            }
            value={
              <BaseVisualizer
                value="title element - value"
                id="test-id-value"
              />
            }
          />,
          <VerticalListVisualizer
            id="test-id-list"
            name={
              <BaseVisualizer
                value="vertical list element - name"
                id="test-id-vlist"
              />
            }
            values={[
              <BaseVisualizer
                value="vertical list element - first element"
                id="test-id-value"
              />,
            ]}
          />,
        ]}
        alignment="between"
      />,
    );

    screen.debug();

    // check alignment
    expect(container.firstChild.className).toContain("justify-content-between");
    expect(screen.getByText("base element")).toBeInTheDocument();
    expect(screen.getByText("bool element")).toBeInTheDocument();
    expect(screen.getByText("title element - title")).toBeInTheDocument();
    expect(
      screen.getByText("vertical list element - name"),
    ).toBeInTheDocument();
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });
});
