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

    const { container } = render(
      <BrowserRouter>
        <AppHeader />
      </BrowserRouter>,
    );

    // header nav - left side
    const navbarLeftSide = container.querySelector(`#navbar-left-side`);
    expect(navbarLeftSide).toBeInTheDocument();
    expect(navbarLeftSide.className).toContain("navbar-nav");

    const analyzablesButton = screen.getByText("Analyzables");
    expect(analyzablesButton).toBeInTheDocument();
    expect(analyzablesButton.closest("a").href).toContain("/analyzables");

    const dashboardButton = screen.getByText("Dashboard");
    expect(dashboardButton).toBeInTheDocument();
    expect(dashboardButton.closest("a").href).toContain("/dashboard");

    const historyButton = screen.getByText("History");
    expect(historyButton).toBeInTheDocument();
    expect(historyButton.closest("a").href).toContain("/history");

    const reportsButton = screen.getByText("Reports");
    expect(reportsButton).toBeInTheDocument();
    expect(reportsButton.closest("a").href).toContain("/search");

    const pluginsButton = screen.getByText("Plugins");
    expect(pluginsButton).toBeInTheDocument();
    expect(pluginsButton.closest("a").href).toContain("/plugins");

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
  });

  test("auth header - no org", async () => {
    useAuthStore.mockImplementation(
      jest.fn((state) => state(mockedUseAuthStore)),
    );
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const { container } = render(
      <BrowserRouter>
        <AppHeader />
      </BrowserRouter>,
    );

    // header nav - left side
    const navbarLeftSide = container.querySelector(`#navbar-left-side`);
    expect(navbarLeftSide).toBeInTheDocument();
    expect(navbarLeftSide.className).toContain("navbar-nav");

    const analyzablesButton = screen.getByText("Analyzables");
    expect(analyzablesButton).toBeInTheDocument();
    expect(analyzablesButton.closest("a").href).toContain("/analyzables");

    const dashboardButton = screen.getByText("Dashboard");
    expect(dashboardButton).toBeInTheDocument();
    expect(dashboardButton.closest("a").href).toContain("/dashboard");

    const historyButton = screen.getByText("History");
    expect(historyButton).toBeInTheDocument();
    expect(historyButton.closest("a").href).toContain("/history");

    const reportsButton = screen.getByText("Reports");
    expect(reportsButton).toBeInTheDocument();
    expect(reportsButton.closest("a").href).toContain("/search");

    const pluginsButton = screen.getByText("Plugins");
    expect(pluginsButton).toBeInTheDocument();
    expect(pluginsButton.closest("a").href).toContain("/plugins");

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
  });
});
