import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Visualizers from "../../../../src/components/plugins/types/Visualizers";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUsePluginConfigurationStore,
} from "../../../mock";

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

describe("test Visualizers component", () => {
  test("Table columns", async () => {
    render(
      <BrowserRouter>
        <Visualizers />
      </BrowserRouter>,
    );

    const title = screen.getByRole("heading", { name: "Visualizers 0 total" });
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
    const configuredColumnHeader = screen.getByRole("columnheader", {
      name: "Configured All",
    });
    expect(configuredColumnHeader).toBeInTheDocument();
    const descriptionColumnHeader = screen.getByRole("columnheader", {
      name: "Description",
    });
    expect(descriptionColumnHeader).toBeInTheDocument();
    const playbookConnectedToColumnHeader = screen.getByRole("columnheader", {
      name: "Playbook connected to All",
    });
    expect(playbookConnectedToColumnHeader).toBeInTheDocument();
    const actionColumnHeader = screen.getByRole("columnheader", {
      name: "Actions",
    });
    expect(actionColumnHeader).toBeInTheDocument();
  });
});
