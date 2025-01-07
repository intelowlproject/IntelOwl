import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { PluginConfigContainer } from "../../../src/components/plugins/PluginConfigContainer";
import { useOrganizationStore } from "../../../src/stores/useOrganizationStore";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUseOrganizationStoreOwner,
} from "../../mock";

jest.mock("../../../src/stores/useOrganizationStore");

describe("test PluginConfigContainer component", () => {
  test("plugins config container - no org", async () => {
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    render(
      <BrowserRouter>
        <PluginConfigContainer
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.queryByTestId("orgconfig__AbuseIPDB");
    expect(orgConfigButton).not.toBeInTheDocument(); // no org tab
  });

  test("plugins config container - with org", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
    );

    render(
      <BrowserRouter>
        <PluginConfigContainer
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.getByText("Org config");
    expect(orgConfigButton).toBeInTheDocument();
    expect(orgConfigButton.closest("a").className).not.toContain("active"); // not selected

    // select org tab
    await user.click(orgConfigButton);
    await waitFor(() => {
      expect(userConfigButton.closest("a").className).not.toContain("active"); // not selected
      expect(orgConfigButton.closest("a").className).toContain("active"); // selected
    });
  });
});
