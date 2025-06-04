import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TableVisualizer } from "../../../../../../src/components/common/visualizer/elements/table";
import { BaseVisualizer } from "../../../../../../src/components/common/visualizer/elements/base";

// mock useLocation
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useLocation: () => ({
    pathname: "localhost/jobs/123/visualizer",
  }),
}));

describe("TableVisualizer component", () => {
  test("required-only params", async () => {
    const { container } = render(
      <TableVisualizer
        id="test-id"
        size="col-6"
        columns={[
          {
            name: "column_name",
            maxWidth: 300,
            description: "test description",
          },
        ]}
        data={[
          {
            column_name: (
              <BaseVisualizer
                size="auto"
                value="base visualizer test"
                id="test-id-base"
              />
            ),
          },
        ]}
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // check size
    expect(idElement.className).toBe("col-6");
    // check table component
    const tableComponent = screen.getByRole("table");
    expect(tableComponent).toBeInTheDocument();
    // check column header
    const columnHeader = screen.getByText("column name");
    expect(columnHeader).toBeInTheDocument();
    // check toggle sort by
    const toggleSortByButton = screen.getByTitle("Toggle SortBy");
    expect(toggleSortByButton).toBeInTheDocument();
    // check filter
    const filterComponent = container.querySelector(
      "#datatable-select-column_name",
    );
    expect(filterComponent).toBeInTheDocument();
    // check cell text (base visualizer)
    const cellComponent = screen.getByText("base visualizer test");
    expect(cellComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(cellComponent.className).toBe("   ");
    // check tooltip
    const user = userEvent.setup();
    await user.hover(cellComponent);
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
    });
  });

  test("all params", async () => {
    const { container } = render(
      <TableVisualizer
        id="test-id"
        size="col-6"
        alignment="around"
        columns={[
          {
            name: "column_name",
            maxWidth: 300,
            description: "test description",
            disableFilters: true,
            disableSortBy: true,
          },
        ]}
        data={[
          {
            column_name: (
              <BaseVisualizer
                size="auto"
                value="base visualizer test"
                id="test-id-base"
              />
            ),
          },
        ]}
        pageSize={3}
        sortBy={[{ id: "column_name", desc: false }]}
      />,
    );

    // check id
    const idElement = container.querySelector("#test-id");
    expect(idElement).toBeInTheDocument();
    // check size
    expect(idElement.className).toBe("col-6");
    // check table component
    const tableComponent = screen.getByRole("table");
    expect(tableComponent).toBeInTheDocument();
    // check column header
    const columnHeader = screen.getByText("column name");
    expect(columnHeader).toBeInTheDocument();
    // check cell text (base visualizer)
    const cellComponent = screen.getByText("base visualizer test");
    expect(cellComponent).toBeInTheDocument();
    // check color, bold and italic
    expect(cellComponent.className).toBe("   ");
    // check tooltip
    const user = userEvent.setup();
    await user.hover(cellComponent);
    await waitFor(() => {
      const tooltipElement = screen.getByRole("tooltip");
      expect(tooltipElement).toBeInTheDocument();
    });
  });
});
