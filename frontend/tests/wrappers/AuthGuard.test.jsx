import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import Cookies from "js-cookie";

import AuthGuard from "../../src/wrappers/AuthGuard";
import { useAuthStore, CSRF_TOKEN } from "../../src/stores/useAuthStore";
import { addToast } from "@certego/certego-ui";

//mock dependencies
jest.mock("js-cookie");
jest.mock("../../src/stores/useAuthStore");
jest.mock("@certego/certego-ui", () => ({
  FallBackLoading: () => <div data-testid="fallback-loading">Loading...</div>,
  addToast: jest.fn(),
}));

const LocationDisplay = () => {
  const location = useLocation();
  return (
    <div data-testid="location-display">
      {location.pathname}
      {location.search}
    </div>
  );
};

describe("AuthGuard Component", () => {
  let mockLoading = false;
  let mockIsAuthenticated = false;
  let mockFetchUserAccess;

  beforeEach(() => {
    jest.clearAllMocks();
    mockLoading = false;
    mockIsAuthenticated = false;
    mockFetchUserAccess = jest.fn().mockResolvedValue({});
    useAuthStore.mockImplementation(() => [
      mockLoading,
      mockIsAuthenticated,
      mockFetchUserAccess,
    ]);
  });

  const renderAuthGuard = (initialRoute = "/protected") => {
    return render(
      <MemoryRouter initialEntries={[initialRoute]}>
        <Routes>
          <Route
            path="/protected"
            element={
              <AuthGuard>
                <div data-testid="protected-content">Protected Area</div>
              </AuthGuard>
            }
          />
          <Route
            path="/logout"
            element={
              <AuthGuard>
                <div data-testid="protected-content">Logout Area</div>
              </AuthGuard>
            }
          />
          <Route
            path="/login"
            element={<div data-testid="login-page">Login Page</div>}
          />
          <Route
            path="/"
            element={<div data-testid="home-page">Home Page</div>}
          />
        </Routes>
        <LocationDisplay />
      </MemoryRouter>,
    );
  };

  test("renders children if user is authenticated", () => {
    mockIsAuthenticated = true;
    useAuthStore.mockImplementation(() => [
      mockLoading,
      mockIsAuthenticated,
      mockFetchUserAccess,
    ]);
    renderAuthGuard();

    expect(screen.getByTestId("protected-content")).toBeInTheDocument();
    expect(mockFetchUserAccess).not.toHaveBeenCalled();
  });

  test("redirects to login if user is unauthenticated and no cookie is present", () => {
    Cookies.get.mockReturnValue(undefined);

    renderAuthGuard();

    // this should redirect immediately without fetching
    expect(screen.getByTestId("login-page")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-content")).not.toBeInTheDocument();
    expect(mockFetchUserAccess).not.toHaveBeenCalled();
    expect(addToast).toHaveBeenCalledWith(
      "Login required to access the requested page.",
      null,
      "info",
    );
    expect(screen.getByTestId("location-display")).toHaveTextContent(
      "/login?next=/protected",
    );
  });

  test("calls fetchUserAccess if unauthenticated but cookie is present and redirects if still unauthenticated", async () => {
    Cookies.get.mockImplementation((key) => {
      if (key === CSRF_TOKEN) return "dummy-token";
      return undefined;
    });

    renderAuthGuard();

    //the fetch gets called upon mount
    expect(mockFetchUserAccess).toHaveBeenCalled();

    //FallBackLoading should be rendered while checking
    expect(screen.getByTestId("fallback-loading")).toBeInTheDocument();

    //wait until finally block occurs and the component redirects
    await waitFor(() => {
      expect(screen.queryByTestId("fallback-loading")).not.toBeInTheDocument();
    });

    expect(screen.getByTestId("login-page")).toBeInTheDocument();
    expect(addToast).toHaveBeenCalledWith(
      "Login required to access the requested page.",
      null,
      "info",
    );
  });

  test("calls fetchUserAccess if unauthenticated but cookie is present and renders children if auth succeeds", async () => {
    Cookies.get.mockImplementation((key) =>
      key === CSRF_TOKEN ? "dummy-token" : undefined,
    );

    mockFetchUserAccess.mockImplementation(async () => {
      // re-mock the store to return authenticated=true after fetch
      useAuthStore.mockImplementation(() => [false, true, mockFetchUserAccess]);
    });

    renderAuthGuard();

    expect(mockFetchUserAccess).toHaveBeenCalled();
    expect(screen.getByTestId("fallback-loading")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId("protected-content")).toBeInTheDocument();
    });

    expect(addToast).not.toHaveBeenCalled();
  });

  test("redirects to home(/) without ?next if redirecting from a logout path", () => {
    Cookies.get.mockReturnValue(undefined);
    renderAuthGuard("/logout");

    expect(screen.getByTestId("home-page")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-content")).not.toBeInTheDocument();

    expect(screen.getByTestId("location-display")).toHaveTextContent("/");
    expect(screen.getByTestId("location-display")).not.toHaveTextContent(
      "login",
    );

    expect(addToast).not.toHaveBeenCalled();
  });

  test("renders FallBackLoading if store loading is true, regardless of initialCheckDone", () => {
    Cookies.get.mockReturnValue(undefined);
    mockLoading = true;
    useAuthStore.mockImplementation(() => [
      mockLoading,
      mockIsAuthenticated,
      mockFetchUserAccess,
    ]);

    renderAuthGuard();

    //even though there's no cookie, it should show FallBackLoading because store loading is true
    expect(screen.getByTestId("fallback-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("login-page")).not.toBeInTheDocument();
  });
});
