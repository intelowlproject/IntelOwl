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
} from "../../../../src/components/plugins/types/utils";

jest.mock("axios");

describe("PluginHealthCheckButton test", () => {
  test("Health check - status true", async () => {
    const user = userEvent.setup();
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

    await user.click(healthCheckIcon);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/plugin/health_check`,
      );
      expect(screen.getByText("Up and running!")).toBeInTheDocument();
    });
  });

  test("Health check - status false", async () => {
    const user = userEvent.setup();
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

    await user.click(healthCheckIcon);

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
    const user = userEvent.setup();
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

    await user.click(playbookDeletionIcon);
    await expect(screen.getByRole("document", {})).toBeInTheDocument();
    const deleteButton = screen.getByRole("button", {
      name: "Delete",
    });
    expect(deleteButton).toBeInTheDocument();
    const cancelButton = screen.getByRole("button", {
      name: "Cancel",
    });
    expect(cancelButton).toBeInTheDocument();

    await user.click(deleteButton);
    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(`${PLAYBOOKS_CONFIG_URI}/test`);
    });
    // toast
    setTimeout(() => {
      expect(screen.getByText("test deleted")).toBeInTheDocument();
    }, 15 * 1000);
  });
});
