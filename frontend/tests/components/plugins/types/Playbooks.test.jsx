import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Playbooks from "../../../../src/components/plugins/types/Playbooks";

import {
  mockedUseAuthStore,
  mockedUseOrganizationStoreNoOrg,
  mockedUsePluginConfigurationStore,
} from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) => state(mockedUseAuthStore)),
}));
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

describe("test Playbooks component", () => {
  test("Table columns", async () => {
    render(
      <BrowserRouter>
        <Playbooks />
      </BrowserRouter>,
    );

    const title = screen.getByRole("heading", { name: "Playbooks 6 total" });
    expect(title).toBeInTheDocument();
    // table
    const tableComponent = screen.getByRole("table");
    expect(tableComponent).toBeInTheDocument();
    const infoColumnHeader = screen.getByRole("columnheader", { name: "Info" });
    expect(infoColumnHeader).toBeInTheDocument();
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
    const typeColumnHeader = screen.getByRole("columnheader", {
      name: "Supported types All",
    });
    expect(typeColumnHeader).toBeInTheDocument();
    const analyzersExecutedColumnHeader = screen.getByRole("columnheader", {
      name: "Analyzers All",
    });
    expect(analyzersExecutedColumnHeader).toBeInTheDocument();
    const connectorsExecutedColumnHeader = screen.getByRole("columnheader", {
      name: "Connectors All",
    });
    expect(connectorsExecutedColumnHeader).toBeInTheDocument();
    const pivotsExecutedColumnHeader = screen.getByRole("columnheader", {
      name: "Pivots All",
    });
    expect(pivotsExecutedColumnHeader).toBeInTheDocument();
    const visualizersExecutedColumnHeader = screen.getByRole("columnheader", {
      name: "Visualizers All",
    });
    expect(visualizersExecutedColumnHeader).toBeInTheDocument();
    const actionColumnHeader = screen.getByRole("columnheader", {
      name: "Actions",
    });
    expect(actionColumnHeader).toBeInTheDocument();
  });
});
