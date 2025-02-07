import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import PluginsContainer from "../../../src/components/plugins/PluginsContainer";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUsePluginConfigurationStore,
} from "../../mock";

jest.mock("axios");
jest.mock("../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreNoOrg),
  ),
}));
jest.mock("../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

describe("test PluginsContainer component", () => {
  test("plugins page", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/plugins/analyzers"]}>
        <PluginsContainer />
      </MemoryRouter>
    )

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const analyzersButton = screen.getByText("Analyzers");
    expect(analyzersButton).toBeInTheDocument();
    expect(analyzersButton.closest("a").className).toContain("active"); // selected
    const connectorsButton = screen.getByText("Connectors");
    expect(connectorsButton).toBeInTheDocument();
    expect(connectorsButton.closest("a").className).not.toContain("active"); // not selected
    const pivotsButton = screen.getByText("Pivots");
    expect(pivotsButton).toBeInTheDocument();
    expect(pivotsButton.closest("a").className).not.toContain("active"); // not selected
    const visualizersButton = screen.getByText("Visualizers");
    expect(visualizersButton).toBeInTheDocument();
    expect(visualizersButton.closest("a").className).not.toContain("active"); // not selected
    const ingestorsButton = screen.getByText("Ingestors");
    expect(ingestorsButton).toBeInTheDocument();
    expect(ingestorsButton.closest("a").className).not.toContain("active"); // not selected
    const playbooksButton = screen.getByText("Playbooks");
    expect(playbooksButton).toBeInTheDocument();
    expect(playbooksButton.closest("a").className).not.toContain("active"); // not selected

    // connectors tab
    await user.click(connectorsButton);
    await waitFor(() => {
      expect(analyzersButton.closest("a").className).not.toContain("active"); // not selected
      expect(connectorsButton.closest("a").className).toContain("active"); // selected
      expect(pivotsButton.closest("a").className).not.toContain("active"); // not selected
      expect(visualizersButton.closest("a").className).not.toContain("active"); // not selected
      expect(ingestorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(playbooksButton.closest("a").className).not.toContain("active"); // not selected
    });

    // pivots tab
    await user.click(pivotsButton);
    await waitFor(() => {
      expect(analyzersButton.closest("a").className).not.toContain("active"); // not selected
      expect(connectorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(pivotsButton.closest("a").className).toContain("active"); // selected
      expect(visualizersButton.closest("a").className).not.toContain("active"); // not selected
      expect(ingestorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(playbooksButton.closest("a").className).not.toContain("active"); // not selected
    });

    // visualizers tab
    await user.click(visualizersButton);
    await waitFor(() => {
      expect(analyzersButton.closest("a").className).not.toContain("active"); // not selected
      expect(connectorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(pivotsButton.closest("a").className).not.toContain("active"); // not selected
      expect(visualizersButton.closest("a").className).toContain("active"); // selected
      expect(ingestorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(playbooksButton.closest("a").className).not.toContain("active"); // not selected
    });

    // playbooks tab
    await user.click(playbooksButton);
    await waitFor(() => {
      expect(analyzersButton.closest("a").className).not.toContain("active"); // not selected
      expect(connectorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(pivotsButton.closest("a").className).not.toContain("active"); // not selected
      expect(visualizersButton.closest("a").className).not.toContain("active"); // not selected
      expect(ingestorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(playbooksButton.closest("a").className).toContain("active"); //  selected
    });

    // ingestors tab
    await user.click(ingestorsButton);
    await waitFor(() => {
      expect(analyzersButton.closest("a").className).not.toContain("active"); // not selected
      expect(connectorsButton.closest("a").className).not.toContain("active"); // not selected
      expect(pivotsButton.closest("a").className).not.toContain("active"); // not selected
      expect(visualizersButton.closest("a").className).not.toContain("active"); // not selected
      expect(ingestorsButton.closest("a").className).toContain("active"); // selected
      expect(playbooksButton.closest("a").className).not.toContain("active"); // not selected
    });
  });
});
