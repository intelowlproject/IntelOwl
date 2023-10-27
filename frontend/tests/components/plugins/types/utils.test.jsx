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

import {
  PluginHealthCheckButton,
  PlaybooksDeletionButton,
  OrganizationPluginStateToggle,
} from "../../../../src/components/plugins/types/utils";
import {
  mockedUseAuthStore,
  mockedUseOrganizationStoreOwner,
} from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) => state(mockedUseAuthStore)),
}));
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
}));

describe("PluginHealthCheckButton test", () => {
  test("Health check - status true", async () => {
    const userAction = userEvent.setup();
    axios.get.mockImplementation(() =>
      Promise.resolve({ data: { status: true } }),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginHealthCheckButton pluginName="plugin" pluginType_="analyzer" />
      </BrowserRouter>,
    );

    const healthCheckIcon = container.querySelector(
      "#table-pluginhealthcheckbtn__plugin",
    );
    expect(healthCheckIcon).toBeInTheDocument();

    await userAction.click(healthCheckIcon);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/plugin/health_check`,
      );
      expect(screen.getByText("Up and running!")).toBeInTheDocument();
    });
  });

  test("Health check - status false", async () => {
    const userAction = userEvent.setup();
    axios.get.mockImplementation(() =>
      Promise.resolve({ data: { status: false } }),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginHealthCheckButton pluginName="plugin" pluginType_="analyzer" />
      </BrowserRouter>,
    );

    const healthCheckIcon = container.querySelector(
      "#table-pluginhealthcheckbtn__plugin",
    );
    expect(healthCheckIcon).toBeInTheDocument();

    await userAction.click(healthCheckIcon);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/plugin/health_check`,
      );
      expect(screen.getByText("Failing!")).toBeInTheDocument();
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
    setTimeout(() => {
      expect(screen.getByText("test deleted")).toBeInTheDocument();
    }, 15 * 1000);
  });
});

describe("OrganizationPluginStateToggle test", () => {
  test("Enable custom playbook for org", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled
          pluginName="plugin"
          type="playbook"
          refetch={jest.fn()}
          pluginOwner="user_owner"
        />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector("#table-pluginstatebtn__plugin");
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(
        `${API_BASE_URI}/playbook/plugin`,
        { for_organization: true },
      );
    });
  });

  test("Disable custom playbook for org", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled={false}
          pluginName="plugin"
          type="playbook"
          refetch={jest.fn()}
          pluginOwner="user_owner"
        />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector("#table-pluginstatebtn__plugin");
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(
        `${API_BASE_URI}/playbook/plugin`,
        { for_organization: false },
      );
    });
  });

  test("Enable default playbook for org", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.delete.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.post.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled
          pluginName="plugin"
          type="playbook"
          refetch={jest.fn()}
        />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector("#table-pluginstatebtn__plugin");
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(
        `${API_BASE_URI}/playbook/plugin/organization`,
      );
    });
  });

  test("Disable default playbook for org", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.delete.mockImplementation(() => Promise.resolve({ data: {} }));
    axios.post.mockImplementation(() => Promise.resolve({ data: {} }));

    const { container } = render(
      <BrowserRouter>
        <OrganizationPluginStateToggle
          disabled={false}
          pluginName="plugin"
          type="playbook"
          refetch={jest.fn()}
        />
      </BrowserRouter>,
    );

    const iconButton = container.querySelector("#table-pluginstatebtn__plugin");
    expect(iconButton).toBeInTheDocument();

    await userAction.click(iconButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${API_BASE_URI}/playbook/plugin/organization`,
      );
    });
  });
});
