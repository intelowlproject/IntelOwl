import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Connectors from "../../../../src/components/plugins/tables/Connectors";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUsePluginConfigurationStore,
} from "../../../mock";

jest.mock("reactflow/dist/style.css", () => {});
jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreNoOrg),
  ),
}));
jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

describe("test Connectors component", () => {
  test("Table columns", async () => {
    render(
      <BrowserRouter>
        <Connectors />
      </BrowserRouter>,
    );

    const title = screen.getByRole("heading", { name: "Connectors 1 total" });
    expect(title).toBeInTheDocument();
    // table
    const tableComponent = screen.getByRole("table");
    expect(tableComponent).toBeInTheDocument();
    const nameColumnHeader = screen.getByRole("columnheader", { name: "Name" });
    expect(nameColumnHeader).toBeInTheDocument();
    const activeColumnHeader = screen.getByRole("columnheader", {
      name: "Active All",
    });
    expect(activeColumnHeader).toBeInTheDocument();
    const descriptionColumnHeader = screen.getByRole("columnheader", {
      name: "Description",
    });
    expect(descriptionColumnHeader).toBeInTheDocument();
    const tlpColumnHeader = screen.getByRole("columnheader", {
      name: "Maximum TLP All",
    });
    expect(tlpColumnHeader).toBeInTheDocument();
    const actionColumnHeader = screen.getByRole("columnheader", {
      name: "Actions",
    });
    expect(actionColumnHeader).toBeInTheDocument();
  });
});
