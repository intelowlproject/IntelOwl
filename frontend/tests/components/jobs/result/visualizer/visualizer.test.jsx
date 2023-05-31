import React from "react";
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";
import VisualizerReport from "../../../../../src/components/jobs/result/visualizer/visualizer";

describe("test VisualizerReport (conversion from backend data to frontend components)", () => {
  test("visualizer failed with error", () => {
    render(
      <VisualizerReport
        visualizerReport={{
          id: 104,
          name: "DNS",
          process_time: 0.03,
          report: [],
          status: "FAILED",
          errors: ["division by zero"],
          start_time: "2023-05-30T13:45:04.942529Z",
          end_time: "2023-05-30T13:45:04.972004Z",
          runtime_configuration: {},
          type: "visualizer",
        }}
      />
    );

    // check error
    expect(screen.getByText("Error!")).toBeInTheDocument();
    expect(
      screen.getByText("An error occurred during the rendering")
    ).toBeInTheDocument();
    expect(screen.getByText("division by zero")).toBeInTheDocument();
  });

  test("valid data", () => {
    /** Simply ceck that data are converted into components:
     * we have other tests to check the validation and the specific components.
     */
    const { container } = render(
      <VisualizerReport
        visualizerReport={{
          id: 105,
          name: "DNS",
          process_time: 0.04,
          report: [
            {
              level: 2,
              elements: {
                type: "horizontal_list",
                values: [
                  {
                    icon: "",
                    link: "",
                    size: "auto",
                    type: "base",
                    color: "danger",
                    bold: false,
                    value: "base component",
                    italic: false,
                    disable: true,
                  },
                  {
                    icon: "",
                    link: "",
                    size: "auto",
                    type: "bool",
                    color: "danger",
                    value: "bool component",
                    italic: false,
                    disable: true,
                  },
                ],
                alignment: "around",
              },
            },
            {
              level: 1,
              elements: {
                type: "horizontal_list",
                values: [
                  {
                    name: {
                      bold: false,
                      icon: "",
                      link: "",
                      size: "auto",
                      type: "base",
                      color: "",
                      value: "vlist title",
                      italic: false,
                      disable: false,
                      alignment: "center",
                    },
                    open: true,
                    size: "auto",
                    type: "vertical_list",
                    values: [
                      {
                        bold: false,
                        icon: "",
                        link: "",
                        size: "auto",
                        type: "base",
                        color: "",
                        value: "vlist element",
                        italic: false,
                        disable: false,
                        alignment: "center",
                      },
                    ],
                    disable: false,
                    alignment: "center",
                  },
                  {
                    title: {
                      bold: false,
                      icon: "",
                      link: "",
                      size: "auto",
                      type: "base",
                      color: "",
                      value: "title title",
                      italic: false,
                      disable: false,
                      alignment: "center",
                    },
                    size: "auto",
                    type: "title",
                    value: {
                      bold: false,
                      icon: "",
                      link: "",
                      size: "auto",
                      type: "base",
                      color: "",
                      value: "title value",
                      italic: false,
                      disable: false,
                      alignment: "center",
                    },
                    disable: false,
                    alignment: "center",
                  },
                ],
                alignment: "around",
              },
            },
          ],
          status: "SUCCESS",
          errors: [],
          start_time: "2023-05-30T14:03:21.873898Z",
          end_time: "2023-05-30T14:03:21.915887Z",
          runtime_configuration: {},
          type: "visualizer",
        }}
      />
    );

    // check the first line has vlist and title and NOT base and bool
    const vListComponent = within(container.firstChild.firstChild).getByText(
      "vlist title"
    );
    expect(vListComponent).toBeInTheDocument();
    const titleComponent = within(container.firstChild.firstChild).getByText(
      "title title"
    );
    expect(titleComponent).toBeInTheDocument();
    expect(
      within(container.firstChild.firstChild).queryByText("base component")
    ).toBeNull();
    expect(
      within(container.firstChild.firstChild).queryByText("bool component")
    ).toBeNull();
    // check base and bool are still present in the document
    expect(screen.getByText("base component")).toBeInTheDocument();
    expect(screen.getByText("bool component")).toBeInTheDocument();
  });
});
