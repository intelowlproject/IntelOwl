import React from "react";
import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import NotificationsList from "../../../../src/components/jobs/notification/NotificationsList";
import { notificationMarkAsRead } from "../../../../src/components/jobs/notification/notificationApi";

// Mock the API calls
jest.mock(
  "../../../../src/components/jobs/notification/notificationApi",
  () => ({
    notificationMarkAsRead: jest.fn(),
  }),
);

// Mock react-icons
jest.mock("react-icons/io5", () => ({
  IoCheckmarkDoneSharp: () => <div data-testid="check-icon" />,
}));

// Mock certego-ui components
jest.mock("@certego/certego-ui", () => ({
  ContentSection: ({ children }) => <div>{children}</div>,
  IconButton: (props) => <button {...props}>{props.title}</button>,
  DateHoverable: () => <span>Date</span>,
}));

describe("NotificationsList Component - Security & XSS Prevention", () => {
  const mockRefetch = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("XSS Prevention - Critical Tests", () => {
    test("prevents <script> tag execution", () => {
      const notifications = [
        {
          id: 1,
          title: "XSS Script Test",
          body: '<script>alert("XSS")</script>',
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const scripts = container.querySelectorAll("script");
      expect(scripts.length).toBe(0);
    });

    test("prevents inline event handler (onerror)", () => {
      const notifications = [
        {
          id: 2,
          title: "XSS Event Test",
          body: '<img src="x" onerror="alert(\'XSS\')">',
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const images = container.querySelectorAll("img[onerror]");
      expect(images.length).toBe(0);
    });

    test("prevents iframe injection", () => {
      const notifications = [
        {
          id: 3,
          title: "Iframe Test",
          body: "<iframe src=\"javascript:alert('XSS')\"></iframe>",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const iframes = container.querySelectorAll("iframe");
      expect(iframes.length).toBe(0);
    });

    test("prevents javascript: protocol in links", () => {
      const notifications = [
        {
          id: 4,
          title: "JS Protocol Test",
          body: '[Click me](javascript:alert("XSS"))',
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const link = screen.queryByRole("link");
      expect(link).not.toBeInTheDocument();
    });

    test("prevents onclick attribute injection", () => {
      const notifications = [
        {
          id: 5,
          title: "Onclick Test",
          body: "<div onclick=\"alert('XSS')\">Click me</div>",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const elemsWithOnclick = container.querySelectorAll("[onclick]");
      expect(elemsWithOnclick.length).toBe(0);
    });
  });

  describe("Markdown Rendering", () => {
    test("renders bold markdown correctly", () => {
      const notifications = [
        {
          id: 6,
          title: "Bold Test",
          body: "This is **bold** text",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      // Re-checking standard markdown rendering.
      // React-markdown usually maps strong to strong.
      // If this fails we might need to check just text content or specific html structure.
      // But let's assume standard behavior as the user provided.
      const strongElement = container.querySelector("strong");
      expect(strongElement).toBeInTheDocument();
      expect(strongElement).toHaveTextContent("bold");
    });

    test("renders italic markdown with custom component", () => {
      const notifications = [
        {
          id: 7,
          title: "Italic Test",
          body: "This is *italic* text",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      const { container } = render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const italicElement = container.querySelector("i.text-code");
      expect(italicElement).toBeInTheDocument();
    });

    test('renders markdown links with target="_blank"', () => {
      const notifications = [
        {
          id: 8,
          title: "Link Test",
          body: "[Google](https://google.com)",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const link = screen.getByRole("link", { name: "Google" });
      expect(link).toHaveAttribute("href", "https://google.com");
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
      expect(link).toHaveClass("link-primary");
    });
  });

  describe("Functionality Tests", () => {
    test("calls markAsRead when button clicked", () => {
      const notifications = [
        {
          id: 9,
          title: "Test",
          body: "Test body",
          read: false,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      const markReadButton = screen.getByTitle("mark as read");
      fireEvent.click(markReadButton);

      expect(notificationMarkAsRead).toHaveBeenCalledWith(9);
    });

    test("does not show button for read notifications", () => {
      const notifications = [
        {
          id: 10,
          title: "Read Notification",
          body: "Already read",
          read: true,
          created_at: "2023-01-01T00:00:00Z",
        },
      ];

      render(
        <NotificationsList
          notifications={notifications}
          refetchFn={mockRefetch}
        />,
      );

      expect(screen.queryByTitle("mark as read")).not.toBeInTheDocument();
    });

    test('shows "No items" when empty', () => {
      render(<NotificationsList notifications={[]} refetchFn={mockRefetch} />);

      expect(screen.getByText("No items")).toBeInTheDocument();
    });
  });
});
