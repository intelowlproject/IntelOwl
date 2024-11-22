import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import AppHeader from "../../src/layouts/AppHeader";
import { useAuthStore } from "../../src/stores/useAuthStore";
import { useOrganizationStore } from "../../src/stores/useOrganizationStore";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUseOrganizationStoreOwner,
  mockedUseAuthStore,
  mockedUseAuthStoreNoAuth,
} from "../mock";

jest.mock("../../src/stores/useAuthStore");
jest.mock("../../src/stores/useOrganizationStore");

describe("test AppHeader component", () => {
  test("no auth header", async () => {
    useAuthStore.mockImplementation(
      jest.fn((state) => state(mockedUseAuthStoreNoAuth)),
    );
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <AppHeader />
      </BrowserRouter>,
    );

    // header nav - left side
    const navbarLeftSide = container.querySelector(`#navbar-left-side`);
    expect(navbarLeftSide).toBeInTheDocument();
    expect(navbarLeftSide.className).toContain("navbar-nav");

    const homeButton = screen.getByText("Home");
    expect(homeButton).toBeInTheDocument();
    expect(homeButton.closest("a").href).toContain("/");

    // header nav - right side
    const navbarRightSide = container.querySelector(`#navbar-right-side`);
    expect(navbarRightSide).toBeInTheDocument();
    expect(navbarRightSide.className).toContain("navbar-nav");

    const docsButton = screen.getByText("Docs");
    expect(docsButton).toBeInTheDocument();
    expect(docsButton.closest("a").href).toBe(
      "https://intelowlproject.github.io/docs/",
    );

    const socialButton = screen.getByText("Social");
    expect(socialButton).toBeInTheDocument();

    const loginButton = screen.getByText("Login");
    expect(loginButton).toBeInTheDocument();

    const registerButton = screen.getByText("Register");
    expect(registerButton).toBeInTheDocument();

    await user.click(socialButton);
    await waitFor(() => {
      expect(screen.getByText("Follow @intel_owl")).toBeInTheDocument();
      expect(screen.getByText("Connect on Github")).toBeInTheDocument();
      expect(screen.getByText("IntelOwl on LinkedIn")).toBeInTheDocument();
      expect(screen.getByText("Honeynet on GSOC")).toBeInTheDocument();
      expect(screen.getByText("Honeynet Slack Chat")).toBeInTheDocument();
    });
  });

  test("auth header - with org", async () => {
    useAuthStore.mockImplementation(
      jest.fn((state) => state(mockedUseAuthStore)),
    );
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
    );

    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <AppHeader />
      </BrowserRouter>,
    );

    // header nav - left side
    const navbarLeftSide = container.querySelector(`#navbar-left-side`);
    expect(navbarLeftSide).toBeInTheDocument();
    expect(navbarLeftSide.className).toContain("navbar-nav");

    const homeButton = screen.getByText("Home");
    expect(homeButton).toBeInTheDocument();
    expect(homeButton.closest("a").href).toContain("/");

    const dashboardButton = screen.getByText("Dashboard");
    expect(dashboardButton).toBeInTheDocument();
    expect(dashboardButton.closest("a").href).toContain("/dashboard");

    const historyButton = screen.getByText("History");
    expect(historyButton).toBeInTheDocument();
    expect(historyButton.closest("a").href).toContain("/history");

    const pluginsButton = screen.getByText("Plugins");
    expect(pluginsButton).toBeInTheDocument();

    const scanButton = screen.getByText("Scan");
    expect(scanButton).toBeInTheDocument();
    expect(scanButton.closest("a").href).toContain("/scan");

    // header nav - right side
    const navbarRightSide = container.querySelector(`#navbar-right-side`);
    expect(navbarRightSide).toBeInTheDocument();
    expect(navbarRightSide.className).toContain("navbar-nav");

    const docsButton = screen.getByText("Docs");
    expect(docsButton).toBeInTheDocument();
    expect(docsButton.closest("a").href).toBe(
      "https://intelowlproject.github.io/docs/",
    );

    const socialButton = screen.getByText("Social");
    expect(socialButton).toBeInTheDocument();

    await user.hover(pluginsButton);
    await waitFor(() => {
      const pluginsListButton = screen.getByText("Plugins List");
      expect(pluginsListButton).toBeInTheDocument();
      expect(pluginsListButton.closest("a").href).toContain("/plugins");
      const pluginsConfigButton = screen.getByText("User Plugin Config");
      expect(pluginsConfigButton).toBeInTheDocument();
      expect(pluginsConfigButton.closest("a").href).toContain("/me/config");
      const pluginsOrgConfigButton = screen.getByText(
        "Organization Plugin Config",
      );
      expect(pluginsOrgConfigButton).toBeInTheDocument();
      expect(pluginsOrgConfigButton.closest("a").href).toContain(
        "/me/organization/config",
      );
    });
  });

  test("auth header - no org", async () => {
    useAuthStore.mockImplementation(
      jest.fn((state) => state(mockedUseAuthStore)),
    );
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <AppHeader />
      </BrowserRouter>,
    );

    // header nav - left side
    const navbarLeftSide = container.querySelector(`#navbar-left-side`);
    expect(navbarLeftSide).toBeInTheDocument();
    expect(navbarLeftSide.className).toContain("navbar-nav");

    const homeButton = screen.getByText("Home");
    expect(homeButton).toBeInTheDocument();
    expect(homeButton.closest("a").href).toContain("/");

    const dashboardButton = screen.getByText("Dashboard");
    expect(dashboardButton).toBeInTheDocument();
    expect(dashboardButton.closest("a").href).toContain("/dashboard");

    const historyButton = screen.getByText("History");
    expect(historyButton).toBeInTheDocument();
    expect(historyButton.closest("a").href).toContain("/history");

    const pluginsButton = screen.getByText("Plugins");
    expect(pluginsButton).toBeInTheDocument();

    const scanButton = screen.getByText("Scan");
    expect(scanButton).toBeInTheDocument();
    expect(scanButton.closest("a").href).toContain("/scan");

    // header nav - right side
    const navbarRightSide = container.querySelector(`#navbar-right-side`);
    expect(navbarRightSide).toBeInTheDocument();
    expect(navbarRightSide.className).toContain("navbar-nav");

    const docsButton = screen.getByText("Docs");
    expect(docsButton).toBeInTheDocument();
    expect(docsButton.closest("a").href).toBe(
      "https://intelowlproject.github.io/docs/",
    );

    const socialButton = screen.getByText("Social");
    expect(socialButton).toBeInTheDocument();

    await user.hover(pluginsButton);
    await waitFor(() => {
      const pluginsListButton = screen.getByText("Plugins List");
      expect(pluginsListButton).toBeInTheDocument();
      expect(pluginsListButton.closest("a").href).toContain("/plugins");
      const pluginsConfigButton = screen.getByText("User Plugin Config");
      expect(pluginsConfigButton).toBeInTheDocument();
      expect(pluginsConfigButton.closest("a").href).toContain("/me/config");
    });
  });
});
