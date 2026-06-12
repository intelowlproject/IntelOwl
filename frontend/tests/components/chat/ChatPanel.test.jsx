import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, act, fireEvent } from "@testing-library/react";

import { ChatPanel } from "../../../src/components/chat/ChatPanel";
import {
  useChatStore,
  ConnectionState,
  MessageRole,
} from "../../../src/stores/useChatStore";

jest.mock("axios");

// No-op WebSocket so the lazily-connecting hook does not touch the network in jsdom. It opens on
// the next tick so the hook transitions CONNECTING -> CONNECTED like a real socket.
class StubWebSocket {
  constructor() {
    this.readyState = StubWebSocket.OPEN;
    setTimeout(() => {
      if (this.onopen) this.onopen({});
    }, 0);
  }

  // eslint-disable-next-line class-methods-use-this
  send() {}

  // eslint-disable-next-line class-methods-use-this
  close() {}
}
StubWebSocket.OPEN = 1;

const baseState = {
  isOpen: true,
  sessionId: null,
  messages: [],
  streamingText: "",
  currentTool: null,
  isStreaming: false,
  connectionState: ConnectionState.CONNECTED,
  error: null,
  sessions: [],
  sessionsLoading: false,
  sessionsError: null,
  historyLoading: false,
  navEpoch: 0,
  assistantUnavailable: false,
};

describe("ChatPanel", () => {
  beforeAll(() => {
    window.HTMLElement.prototype.scrollIntoView = jest.fn();
  });

  beforeEach(() => {
    global.WebSocket = StubWebSocket;
    useChatStore.setState(baseState);
    // the drawer-open effect probes /health (assistant healthy by default) and the sessions view
    // fetches the list on mount; route by URL so the open-probe never reads a sessions payload.
    axios.get.mockImplementation((url) =>
      url.includes("/health")
        ? Promise.resolve({ data: { available: true, detail: "" } })
        : Promise.resolve({ data: { total_pages: 1, results: [] } }),
    );
  });

  test("renders the composer and the connection badge when open", async () => {
    render(<ChatPanel />);
    expect(screen.getByPlaceholderText(/Ask about/i)).toBeInTheDocument();
    // the hook flips CONNECTING -> CONNECTED once the (stub) socket opens
    expect(await screen.findByText("Connected")).toBeInTheDocument();
  });

  test("shows an Unavailable badge when the assistant is unavailable while connected", async () => {
    // the open-probe reports the assistant down, so the flag stays set once it resolves
    axios.get.mockImplementation((url) =>
      url.includes("/health")
        ? Promise.resolve({ data: { available: false, detail: "down" } })
        : Promise.resolve({ data: { total_pages: 1, results: [] } }),
    );
    useChatStore.setState({ assistantUnavailable: true });
    render(<ChatPanel />);
    // the socket is connected (transport fine) but the assistant can't serve a turn: the badge must
    // say so instead of staying green "Connected".
    expect(await screen.findByText("Unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Connected")).not.toBeInTheDocument();
  });

  test("renders an info tooltip describing the assistant", () => {
    render(<ChatPanel />);
    expect(document.getElementById("chat-assistant-info")).toBeInTheDocument();
  });

  test("renders the conversation from store state", () => {
    useChatStore.setState({
      messages: [
        { role: MessageRole.USER, content: "show my jobs" },
        { id: 1, role: MessageRole.ASSISTANT, content: "Here they are" },
      ],
    });
    render(<ChatPanel />);
    expect(screen.getByText("show my jobs")).toBeInTheDocument();
    expect(screen.getByText("Here they are")).toBeInTheDocument();
  });

  test("surfaces an error banner", () => {
    render(<ChatPanel />);
    act(() => {
      useChatStore
        .getState()
        .applyError(
          "The assistant is currently unavailable. Please try again.",
        );
    });
    expect(screen.getByText(/currently unavailable/i)).toBeInTheDocument();
  });

  test("toggles between the conversation and the sessions view", async () => {
    render(<ChatPanel />);
    // starts on the conversation view
    expect(screen.getByPlaceholderText(/Ask about/i)).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Show conversations/i }),
    );
    // sessions view: New chat present, composer gone
    expect(
      await screen.findByRole("button", { name: /New chat/i }),
    ).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/Ask about/i)).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Back to conversation/i }),
    );
    expect(screen.getByPlaceholderText(/Ask about/i)).toBeInTheDocument();
  });

  test("probes health when the drawer opens and surfaces an unavailable result", async () => {
    axios.get.mockImplementation((url) =>
      url.includes("/health")
        ? Promise.resolve({
            data: { available: false, detail: "Services down" },
          })
        : Promise.resolve({ data: { total_pages: 1, results: [] } }),
    );
    render(<ChatPanel />); // baseState has isOpen: true -> the open effect fires checkHealth
    expect(await screen.findByText("Services down")).toBeInTheDocument();
    expect(await screen.findByText("Unavailable")).toBeInTheDocument();
  });
});
