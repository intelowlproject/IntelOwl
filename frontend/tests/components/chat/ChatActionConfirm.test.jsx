import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";

import { ChatActionConfirm } from "../../../src/components/chat/ChatActionConfirm";
import { useChatStore } from "../../../src/stores/useChatStore";

const PLAN = {
  observable_name: "example.com",
  classification: "domain",
  tlp: "CLEAR",
  playbook: null,
  analyzers: ["Tranco"],
  connectors: [],
  skipped: [],
};

describe("ChatActionConfirm", () => {
  afterEach(() => useChatStore.setState({ pendingAction: null }));

  it("renders nothing when there is no pending action", () => {
    useChatStore.setState({ pendingAction: null });
    const { container } = render(<ChatActionConfirm />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the plan and triggers confirm on click", async () => {
    const confirmPendingAction = jest.fn();
    useChatStore.setState({
      pendingAction: { pendingId: "abc", plan: PLAN },
      confirmPendingAction,
      isStreaming: false,
    });
    render(<ChatActionConfirm />);
    expect(screen.getByText(/example\.com/)).toBeInTheDocument();
    expect(screen.getByText(/Tranco/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /confirm/i }));
    expect(confirmPendingAction).toHaveBeenCalled();
  });

  it("renders without crashing when the plan omits the optional arrays", () => {
    useChatStore.setState({
      pendingAction: {
        pendingId: "abc",
        plan: {
          observable_name: "1.1.1.1",
          classification: "ip",
          tlp: "CLEAR",
        },
      },
    });
    render(<ChatActionConfirm />);
    // arrays absent -> analyzers falls back to "default", no Connectors/Skipped rows
    expect(screen.getByText(/Analyzers: default/)).toBeInTheDocument();
    expect(screen.queryByText(/Connectors:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Skipped:/)).not.toBeInTheDocument();
  });

  it("cancels on click", async () => {
    const cancelPendingAction = jest.fn();
    useChatStore.setState({
      pendingAction: { pendingId: "abc", plan: PLAN },
      cancelPendingAction,
    });
    render(<ChatActionConfirm />);
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(cancelPendingAction).toHaveBeenCalled();
  });
});
