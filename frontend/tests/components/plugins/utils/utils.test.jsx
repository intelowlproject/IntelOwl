import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { API_BASE_URI } from "../../../../src/constants/api";
import {
  parseScanCheckTime,
  PluginHealthCheckButton,
} from "../../../../src/components/plugins/utils/utils";

jest.mock("axios");

describe("parseScanCheckTime test", () => {
  test("correct time: days:hours:minutes:seconds", () => {
    const time = parseScanCheckTime("01:02:00:00");
    expect(time).toBe(26);
  });

  test("not correct time: days-hours-minutes-seconds", () => {
    const time = parseScanCheckTime("01-02-00-00");
    expect(time).toBe(NaN);
  });
});

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
