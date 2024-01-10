import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import {
  API_BASE_URI,
  PLAYBOOKS_CONFIG_URI,
} from "../../../../src/constants/apiURLs";
import Toast from "../../../../src/layouts/Toast";
import {
  PluginHealthCheckButton,
  PlaybooksDeletionButton,
  OrganizationPluginStateToggle,
  PluginPullButton,
} from "../../../../src/components/plugins/types/pluginActionsButtons";
import { mockedUseOrganizationStoreOwner } from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreOwner),
  ),
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

describe("PlaybooksDeletionButton test", () => {
  test("playbook deletion", async () => {
    const userAction = userEvent.setup();
    axios.delete.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <PlaybooksDeletionButton playbookName="test" />
        <Toast />
      </BrowserRouter>,
    );

    const playbookDeletionIcon = container.querySelector(
      "#playbook-deletion-test",
    );
    expect(playbookDeletionIcon).toBeInTheDocument();

    await userAction.click(playbookDeletionIcon);
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
      expect(axios.delete).toHaveBeenCalledWith(`${PLAYBOOKS_CONFIG_URI}/test`);
    });
    // toast
    expect(screen.getByText("test deleted")).toBeInTheDocument();
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
