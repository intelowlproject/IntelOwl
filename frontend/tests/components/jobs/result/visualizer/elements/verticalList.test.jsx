import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BaseVisualizer } from "../../../../../../src/components/common/visualizer/elements/base";
import { VerticalListVisualizer } from "../../../../../../src/components/common/visualizer/elements/verticalList";
import { HorizontalListVisualizer } from "../../../../../../src/components/common/visualizer/elements/horizontalList";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("VerticalListVisualizer component", () => {
  test("required-only params", () => {
    const { container } = render(
      <VerticalListVisualizer
        id="test-id"
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (required-only params)"
            color="warning"
            id="test-id-vlist"
          />
        }
        values={[
          <BaseVisualizer
            size="auto"
            value="first line - single element"
            id="test-id-base"
          />,
          <HorizontalListVisualizer
            id="test-id-hlist"
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
                id="test-id-hlist-1"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
                id="test-id-hlist-2"
              />,
            ]}
          />,
        ]}
      />,
    );

    // check title
    expect(
      screen.getByText("title (required-only params)"),
    ).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element"),
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    // check button
    const dropdownButton = screen.getByRole("button", {
      name: "title (required-only params)",
    });
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-warning");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });

  test("all params", () => {
    const { container } = render(
      <VerticalListVisualizer
        id="test-id"
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (all params)"
            color="success"
            id="test-id-vlist"
          />
        }
        values={[
          <BaseVisualizer
            size="auto"
            value="first line - single element"
            id="test-id-base"
          />,
          <HorizontalListVisualizer
            id="test-id-hlist"
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
                id="test-id-hlist-1"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
                id="test-id-hlist-2"
              />,
            ]}
          />,
        ]}
        alignment="start"
        startOpen
      />,
    );

    // check title
    expect(screen.getByText("title (all params)")).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element"),
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    expect(mainComponent.firstChild.className).toContain("border-success");
    // check button
    const dropdownButton = screen.getByRole("button", {
      name: "title (all params)",
    });
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-success");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });

  test("all params - disable", () => {
    const { container } = render(
      <VerticalListVisualizer
        id="test-id"
        size="col-2"
        name={
          <BaseVisualizer
            size="auto"
            value="title (all params - disable)"
            color="success"
            id="test-id-vlist"
          />
        }
        values={[
          <BaseVisualizer
            size="auto"
            value="first line - single element"
            id="test-id-base"
          />,
          <HorizontalListVisualizer
            id="test-id-hlist"
            values={[
              <BaseVisualizer
                size="auto"
                value="second line - first element"
                id="test-id-hlist-1"
              />,
              <BaseVisualizer
                size="auto"
                value="second line - second element"
                id="test-id-hlist-2"
              />,
            ]}
          />,
        ]}
        alignment="start"
        startOpen
        disable
      />,
    );

    // check title
    expect(
      screen.getByText("title (all params - disable)"),
    ).toBeInTheDocument();
    // check values
    expect(screen.getByText("first line - single element")).toBeInTheDocument();
    expect(screen.getByText("second line - first element")).toBeInTheDocument();
    expect(
      screen.getByText("second line - second element"),
    ).toBeInTheDocument();
    // check size
    const mainComponent = container.firstChild;
    expect(mainComponent.className).toContain("col-2");
    expect(mainComponent.firstChild.className).toContain("card");
    expect(mainComponent.firstChild.className).toContain("opacity-50");
    expect(mainComponent.firstChild.className).toContain("border-success");
    // check button
    const dropdownButton = screen.getByRole("button", {
      name: "title (all params - disable)",
    });
    expect(dropdownButton).toBeInTheDocument();
    expect(dropdownButton.className).toContain("btn-success");
    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
  });
});
