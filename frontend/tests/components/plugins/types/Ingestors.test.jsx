import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Ingestors from "../../../../src/components/plugins/types/Ingestors";

import { mockedUsePluginConfigurationStore } from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state({
      loading: false,
      error: null,
      isUserOwner: false,
      noOrg: true,
      organization: {},
      membersCount: undefined,
      members: [],
      pendingInvitations: [],
      pluginsState: {},
      fetchAll: () => {},
    }),
  ),
}));
jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));
describe("test Ingestors component", () => {
  test("Table columns", async () => {
    render(
      <BrowserRouter>
        <Ingestors />
      </BrowserRouter>,
    );

    const title = screen.getByRole("heading", { name: "Ingestors 0 total" });
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
    const playbookExecutedColumnHeader = screen.getByRole("columnheader", {
      name: "Playbook executed All",
    });
    expect(playbookExecutedColumnHeader).toBeInTheDocument();
    const scheduleColumnHeader = screen.getByRole("columnheader", {
      name: "Schedule",
    });
    expect(scheduleColumnHeader).toBeInTheDocument();
  });
});
