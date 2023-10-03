import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Analyzers from "../../../../src/components/plugins/utils/Analyzers";

jest.mock("axios");
jest.mock("../../../../src/stores", () => ({
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
  usePluginConfigurationStore: jest.fn((state) =>
    state({
      analyzersLoading: false,
      connectorsLoading: false,
      visualizersLoading: false,
      playbooksLoading: false,
      analyzersError: null,
      connectorsError: null,
      playbooksError: null,
      visualizersError: null,
      analyzers: [
        {
          name: "TEST_ANALYZER",
          config: {
            queue: "default",
            soft_time_limit: 30,
          },
          python_module: "test.Test",
          description: "Test analyzer",
          disabled: false,
          type: "observable",
          docker_based: false,
          maximum_tlp: "AMBER",
          observable_supported: [
            "domain",
            "generic",
            "hash",
            "ip",
            "url",
            "file",
          ],
          supported_filetypes: [],
          run_hash: false,
          run_hash_type: "",
          not_supported_filetypes: [],
          params: {},
          secrets: {},
          verification: {
            configured: true,
            details: "Ready to use!",
            missing_secrets: [],
          },
          orgPluginDisabled: false,
          plugin_type: "1",
        },
      ],
      connectors: [],
      visualizers: [],
      playbooks: [
        {
          name: "TEST_PLAYBOOK_IP",
          type: ["ip"],
          description: "Test playbook for the IP addresses",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 2,
          scan_check_time: "2 00:00:00",
          tags: [
            {
              id: 1,
              label: "test tag",
              color: "#1655D3",
            },
          ],
          tlp: "CLEAR",
          is_deletable: false,
        },
        {
          name: "TEST_PLAYBOOK_DOMAIN",
          type: ["domain"],
          description: "Test playbook for the domains",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 2,
          scan_check_time: "2 00:00:00",
          tags: [],
          tlp: "CLEAR",
          is_deletable: true,
        },
      ],
      hydrate: () => {},
      retrieveAnalyzersConfiguration: () => {},
      retrieveConnectorsConfiguration: () => {},
      retrieveVisualizersConfiguration: () => {},
      retrieveIngestorsConfiguration: () => {},
      retrievePlaybooksConfiguration: () => {},
      checkPluginHealth: () => {},
      deletePlaybook: () => {},
    }),
  ),
}));

describe("test Analyzers component", () => {
  test("Table columns", async () => {
    render(
      <BrowserRouter>
        <Analyzers />
      </BrowserRouter>,
    );

    const title = screen.getByRole("heading", { name: "Analyzers 1 total" });
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
    const typeColumnHeader = screen.getByRole("columnheader", {
      name: "Type All",
    });
    expect(typeColumnHeader).toBeInTheDocument();
    const supportedTypesColumnHeader = screen.getByRole("columnheader", {
      name: "Supported types All",
    });
    expect(supportedTypesColumnHeader).toBeInTheDocument();
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
