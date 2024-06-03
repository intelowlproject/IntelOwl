import React from "react";
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";
import VisualizerReport from "../../../../../src/components/jobs/result/visualizer/visualizer";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

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
      />,
    );

    // check error
    expect(screen.getByText("Error!")).toBeInTheDocument();
    expect(
      screen.getByText("An error occurred during the rendering"),
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
              level_position: 2,
              level_size: "2",
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
                    copy_text: "base component",
                    description: "description",
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
                    description: "description",
                  },
                ],
                alignment: "around",
              },
            },
            {
              level_position: 1,
              level_size: "1",
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
                      copy_text: "",
                      description: "description",
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
                        copy_text: "vlist element - copy text",
                        description: "description",
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
                      copy_text: "",
                      description: "description",
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
                      copy_text: "title value - copy text",
                      description: "description",
                    },
                    disable: false,
                    alignment: "center",
                  },
                  {
                    type: "table",
                    size: "auto",
                    alignment: "start",
                    columns: ["column_name"],
                    data: [
                      {
                        column_name: {
                          type: "base",
                          value: "placeholder",
                          icon: "it",
                          color: "success",
                          link: "https://google.com",
                          bold: true,
                          italic: true,
                          disable: false,
                          size: "1",
                          alignment: "start",
                          copy_text: "placeholder",
                          description: "description",
                        },
                      },
                    ],
                    page_size: 5,
                    disable_filters: true,
                    disable_sort_by: true,
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
      />,
    );

    // check level id
    const firstLevelId = container.querySelector("#page105-level1");
    expect(firstLevelId).toBeInTheDocument();
    const secondLevelId = container.querySelector("#page105-level2");
    expect(secondLevelId).toBeInTheDocument();
    // check the first line has vlist, title and table and NOT base and bool
    const vListComponent = within(container.firstChild.firstChild).getByText(
      "vlist title",
    );
    expect(vListComponent).toBeInTheDocument();
    const titleComponent = within(container.firstChild.firstChild).getByText(
      "title title",
    );
    expect(titleComponent).toBeInTheDocument();
    const tableComponent = within(container.firstChild.firstChild).getByText(
      "column name",
    );
    expect(tableComponent).toBeInTheDocument();
    expect(
      within(container.firstChild.firstChild).queryByText("base component"),
    ).toBeNull();
    expect(
      within(container.firstChild.firstChild).queryByText("bool component"),
    ).toBeNull();
    // check base and bool are still present in the document
    expect(screen.getByText("base component")).toBeInTheDocument();
    expect(screen.getByText("bool component")).toBeInTheDocument();
  });
});
