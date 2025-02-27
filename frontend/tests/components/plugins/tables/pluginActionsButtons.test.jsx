import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { API_BASE_URI } from "../../../../src/constants/apiURLs";
import Toast from "../../../../src/layouts/Toast";
import {
  PluginHealthCheckButton,
  PluginDeletionButton,
  OrganizationPluginStateToggle,
  PluginPullButton,
  PlaybooksEditButton,
  PluginConfigButton,
  PlaybookFlowsButton,
  MappingDataModel,
} from "../../../../src/components/plugins/tables/pluginActionsButtons";
import {
  mockedUseOrganizationStoreOwner,
  mockedPlaybooks,
} from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreOwner),
  ),
}));
// mock flow component
jest.mock("../../../../src/components/plugins/flows/PlaybookFlows", () => ({
  PlaybookFlows: jest.fn((props) => <div {...props} />),
}));

// current user must be equal to org owner
jest.mock("../../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) =>
    state({
      user: {
        username: "user_owner",
        full_name: "user owner",
        first_name: "user",
        last_name: "owner",
        email: "test@google.com",
      },
    }),
  ),
}));

describe("PluginHealthCheckButton test", () => {
  test.each([
    // healthcheck true
    {
      pluginName: "Plugin1",
      responseData: {
        status: 200,
        data: { status: true },
      },
    },
    // healthcheck false
    {
      pluginName: "Plugin2",
      responseData: {
        status: 200,
        data: { status: false },
      },
    },
  ])("Health check - status 200 (%s)", async ({ pluginName, responseData }) => {
    const userAction = userEvent.setup();
    axios.get.mockImplementation(() => Promise.resolve(responseData));

    const { container } = render(
      <BrowserRouter>
        <PluginHealthCheckButton
          pluginName={pluginName}
          pluginType_="analyzer"
        />
        <Toast />
      </BrowserRouter>,
    );

    const healthCheckIcon = container.querySelector(
      `#table-pluginhealthcheckbtn__${pluginName}`,
    );
    expect(healthCheckIcon).toBeInTheDocument();

    await userAction.click(healthCheckIcon);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/${pluginName}/health_check`,
      );
      // toast
      if (responseData.data.status) {
        // status: true
        expect(
          screen.getByText(`${pluginName} - health check: success`),
        ).toBeInTheDocument();
      } else {
        // status: false
        expect(
          screen.getByText(`${pluginName} - health check: warning`),
        ).toBeInTheDocument();
      }
    });
  });
});

describe("PluginDeletionButton test", () => {
  test.each([
    // playbook
    {
      pluginName: "PlaybookTest",
      pluginType_: "playbook",
    },
    // pivot
    {
      pluginName: "PivotTest",
      pluginType_: "pivot",
    },
  ])("(%s) deletion", async ({ pluginName, pluginType_ }) => {
    const userAction = userEvent.setup();
    axios.delete.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <PluginDeletionButton
          pluginName={pluginName}
          pluginType_={pluginType_}
        />
        <Toast />
      </BrowserRouter>,
    );

    const pluginDeletionIcon = container.querySelector(
      `#plugin-deletion-${pluginName}`,
    );
    expect(pluginDeletionIcon).toBeInTheDocument();

    await userAction.click(pluginDeletionIcon);
    await expect(screen.getByRole("document", {})).toBeInTheDocument();
    const deleteButton = screen.getByRole("button", {
      name: "Delete",
    });
    expect(deleteButton).toBeInTheDocument();
    const cancelButton = screen.getByRole("button", {
      name: "Cancel",
    });
    expect(cancelButton).toBeInTheDocument();

    await userAction.click(deleteButton);
    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(
        `${API_BASE_URI}/${pluginType_}/${pluginName}`,
      );
    });
    // toast
    expect(
      screen.getByText(
        `${pluginType_} with name ${pluginName} deleted with success`,
      ),
    ).toBeInTheDocument();
  });
});

describe("OrganizationPluginStateToggle test", () => {
  test.each([
    // enable playbook
    {
      pluginName: "Plugin3",
      toEnable: true,
    },
    // disable playbook
    {
      pluginName: "Plugin4",
      toEnable: false,
    },
  ])("Custom playbook for org (%s)", async ({ pluginName, toEnable }) => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled={toEnable}
          pluginName={pluginName}
          type="playbook"
          refetch={jest.fn()}
          pluginOwner="user_owner"
        />
        <Toast />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector(
      `#table-pluginstatebtn__${pluginName}`,
    );
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      if (toEnable) {
        expect(axios.patch).toHaveBeenCalledWith(
          `${API_BASE_URI}/playbook/${pluginName}`,
          { for_organization: true },
        );
        // toast
        expect(
          screen.getByText(`${pluginName} enabled for the organization`),
        ).toBeInTheDocument();
      } else {
        expect(axios.patch).toHaveBeenCalledWith(
          `${API_BASE_URI}/playbook/${pluginName}`,
          { for_organization: false },
        );
        // toast
        expect(
          screen.getByText(`${pluginName} disabled for the organization`),
        ).toBeInTheDocument();
      }
    });
  });

  test.each([
    // enable playbook
    {
      pluginName: "Plugin5",
      toEnable: true,
    },
    // disable playbook
    {
      pluginName: "Plugin6",
      toEnable: false,
    },
  ])("Default playbook for org (%s)", async ({ pluginName, toEnable }) => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.delete.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.post.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled={toEnable}
          pluginName={pluginName}
          type="playbook"
          refetch={jest.fn()}
        />
        <Toast />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector(
      `#table-pluginstatebtn__${pluginName}`,
    );
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      if (toEnable) {
        expect(axios.delete).toHaveBeenCalledWith(
          `${API_BASE_URI}/playbook/${pluginName}/organization`,
        );
        // toast
        expect(
          screen.getByText(`${pluginName} enabled for the organization`),
        ).toBeInTheDocument();
      } else {
        expect(axios.post).toHaveBeenCalledWith(
          `${API_BASE_URI}/playbook/${pluginName}/organization`,
        );
        // toast
        expect(
          screen.getByText(`${pluginName} disabled for the organization`),
        ).toBeInTheDocument();
      }
    });
  });
});

describe("PluginPullButton test", () => {
  test.each([
    // pull true
    {
      pluginName: "Plugin7",
      responseData: {
        status: 200,
        data: { status: true },
      },
    },
    // pull false
    {
      pluginName: "Plugin8",
      responseData: {
        status: 200,
        data: { status: false },
      },
    },
  ])("Pull - status 200 (%s)", async ({ pluginName, responseData }) => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve(responseData));

    const { container } = render(
      <BrowserRouter>
        <PluginPullButton pluginName={pluginName} pluginType_="analyzer" />
        <Toast />
      </BrowserRouter>,
    );

    const healthCheckIcon = container.querySelector(
      `#table-pluginpullbtn__${pluginName}`,
    );
    expect(healthCheckIcon).toBeInTheDocument();

    await userAction.click(healthCheckIcon);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/${pluginName}/pull`,
      );
      // toast
      if (responseData.data.status) {
        expect(screen.getByText(`${pluginName} updated`)).toBeInTheDocument();
      } else {
        expect(
          screen.getByText(`${pluginName} pull failed`),
        ).toBeInTheDocument();
      }
    });
  });
});

describe("PlaybooksEditButton test", () => {
  const playbookConfig = {
    id: 13,
    name: "test",
    description: "playbook: test",
    type: ["domain"],
    analyzers: ["TEST_ANALYZER"],
    connectors: ["TEST_CONNECTOR"],
    pivots: [],
    visualizers: [],
    runtime_configuration: {
      pivots: {},
      analyzers: {
        TEST_ANALYZER: {
          query_type: "A",
        },
      },
      connectors: {},
      visualizers: {},
    },
    scan_mode: 2,
    scan_check_time: "0:24:00:00",
    tags: [],
    tlp: "GREEN",
    weight: 0,
    is_editable: true,
    for_organization: true,
    disabled: false,
    starting: true,
    owner: "marti",
    orgPluginDisabled: false,
    plugin_type: "playbook",
  };

  test("Playbook edit btn - loading", async () => {
    const userAction = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <PlaybooksEditButton playbookConfig={playbookConfig} />
      </BrowserRouter>,
    );

    const playbookEditIcon = container.querySelector(
      "#playbook-edit-btn__test",
    );
    expect(playbookEditIcon).toBeInTheDocument();

    await userAction.click(playbookEditIcon);
    // loading tooltip
    expect(
      screen.getByText("Playbook configuration is loading"),
    ).toBeInTheDocument();
  });
});

describe("Plugin Config test", () => {
  test.each([
    // default - configured: true
    {
      pluginConfig: {
        id: 167,
        python_module: "ailtyposquatting.AilTypoSquatting",
        name: "AILTypoSquatting",
        verification: {
          configured: true,
          details: "Ready to use!",
          missing_secrets: [],
        },
        // other configs are not necessary
      },
      buttonClassname: "btn-success",
      tooltipText: "Plugin config",
    },
    // default - configured: false
    {
      pluginConfig: {
        id: 3,
        python_module: "abuseipdb.AbuseIPDB",
        name: "AbuseIPDB",
        verification: {
          configured: false,
          details: "api_key_name secret not set; (3 of 4 satisfied)",
          missing_secrets: ["api_key_name"],
        },
        // other configs are not necessary
      },
      buttonClassname: "btn-warning",
      tooltipText:
        "Plugin config: api_key_name secret not set; (3 of 4 satisfied)",
    },
    // basic analyzer
    {
      pluginConfig: {
        id: 192,
        python_module: "basic_observable_analyzer.BasicObservableAnalyzer",
        name: "AAA_mnemonic_test",
        verification: {
          configured: true,
          details: "Ready to use!",
          missing_secrets: [],
        },
        // other configs are not necessary
      },
      buttonClassname: "btn-success",
      tooltipText: "Edit analyzer config",
    },
  ])(
    "Plugin Config - (%o)",
    async ({ pluginConfig, buttonClassname, tooltipText }) => {
      const userAction = userEvent.setup();

      const { container } = render(
        <BrowserRouter>
          <PluginConfigButton
            pluginConfig={pluginConfig}
            pluginType_="analyzer"
          />
        </BrowserRouter>,
      );

      const configIcon = container.querySelector(
        `#plugin-config-btn__${pluginConfig.name}`,
      );
      expect(configIcon).toBeInTheDocument();
      expect(configIcon.className).toContain(buttonClassname);

      await userAction.hover(configIcon);
      await waitFor(() => {
        expect(screen.getByText(tooltipText)).toBeInTheDocument();
      });
    },
  );
});

describe("PlaybookFlowsButton test", () => {
  test("PlaybookFlowsButton", async () => {
    const userAction = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <PlaybookFlowsButton playbook={mockedPlaybooks.TEST_PLAYBOOK_DOMAIN} />
      </BrowserRouter>,
    );

    const playbookFlowsIcon = container.querySelector(
      "#playbook-flows-btn__TEST_PLAYBOOK_DOMAIN",
    );
    expect(playbookFlowsIcon).toBeInTheDocument();

    userAction.click(playbookFlowsIcon);
    await waitFor(() => {
      expect(screen.getByText("Possible playbook flows")).toBeInTheDocument();
    });
  });
});

describe("DataModel mapping test", () => {
  test("DataModel mapping button", async () => {
    const userAction = userEvent.setup();
    const data = {
      mapping_data_model: {
        permalink: "external_references",
        "data.hostnames": "resolutions",
      },
      type: "observable",
      python_module: "pythonmodule.pythonclass",
    };
    const { container } = render(
      <BrowserRouter>
        <MappingDataModel
          data={data.mapping_data_model}
          type={data.type}
          pythonModule={data.python_module}
        />
      </BrowserRouter>,
    );

    const dataModelMappingIcon = container.querySelector(
      "#mapping-data-model__pythonmodule",
    );
    expect(dataModelMappingIcon).toBeInTheDocument();

    userAction.click(dataModelMappingIcon);
    await waitFor(() => {
      expect(screen.getByText("Data model mapping")).toBeInTheDocument();
    });
  });

  test("DataModel mapping button - disabled", async () => {
    const data = {
      mapping_data_model: {},
      type: "observable",
      python_module: "pythonmodule.pythonclass",
    };
    const { container } = render(
      <BrowserRouter>
        <MappingDataModel
          data={data.mapping_data_model}
          type={data.type}
          pythonModule={data.python_module}
        />
      </BrowserRouter>,
    );

    const dataModelMappingIcon = container.querySelector(
      "#mapping-data-model__pythonmodule",
    );
    expect(dataModelMappingIcon).toBeInTheDocument();
    expect(dataModelMappingIcon.className).toContain("disabled");
  });
});
