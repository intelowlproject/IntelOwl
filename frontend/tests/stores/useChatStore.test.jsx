import axios from "axios";

import {
  useChatStore,
  ConnectionState,
  MessageRole,
  deriveSessionLabel,
} from "../../src/stores/useChatStore";
import { CHATBOT_SESSIONS_URI } from "../../src/constants/apiURLs";

jest.mock("axios");

const initialState = {
  isOpen: false,
  sessionId: null,
  messages: [],
  streamingText: "",
  currentTool: null,
  isStreaming: false,
  connectionState: ConnectionState.IDLE,
  error: null,
  sessions: [],
  sessionsLoading: false,
  sessionsError: null,
  historyLoading: false,
  navEpoch: 0,
  assistantUnavailable: false,
};

describe("useChatStore reducers", () => {
  beforeEach(() => {
    useChatStore.setState(initialState);
  });

  test("toggle flips isOpen", () => {
    useChatStore.getState().toggle();
    expect(useChatStore.getState().isOpen).toBe(true);
    useChatStore.getState().toggle();
    expect(useChatStore.getState().isOpen).toBe(false);
  });

  test("applyAck binds the session id", () => {
    useChatStore.getState().applyAck({ session_id: 42 });
    expect(useChatStore.getState().sessionId).toBe(42);
  });

  test("enqueueUserMessage appends the user message and locks the turn", () => {
    useChatStore.setState({ error: "stale" });
    useChatStore.getState().enqueueUserMessage("hello");
    const state = useChatStore.getState();
    expect(state.messages).toEqual([
      { role: MessageRole.USER, content: "hello" },
    ]);
    expect(state.isStreaming).toBe(true);
    expect(state.error).toBeNull();
  });

  test("applyStart resets the streaming turn", () => {
    useChatStore.setState({
      streamingText: "leftover",
      currentTool: "search_jobs",
    });
    useChatStore.getState().applyStart();
    const state = useChatStore.getState();
    expect(state.streamingText).toBe("");
    expect(state.currentTool).toBeNull();
    expect(state.isStreaming).toBe(true);
  });

  test("applyStatus sets the current tool", () => {
    useChatStore.getState().applyStatus({ tool: "get_job_details" });
    expect(useChatStore.getState().currentTool).toBe("get_job_details");
  });

  test("applyToken appends streaming text incrementally", () => {
    useChatStore.getState().applyToken({ content: "Hel" });
    useChatStore.getState().applyToken({ content: "lo" });
    expect(useChatStore.getState().streamingText).toBe("Hello");
  });

  test("applyEnd commits the assistant message and clears the turn", () => {
    useChatStore.setState({
      streamingText: "Hel",
      currentTool: "search_jobs",
      isStreaming: true,
    });
    useChatStore.getState().applyEnd({ message_id: 7, content: "Hello there" });
    const state = useChatStore.getState();
    expect(state.messages).toEqual([
      { id: 7, role: MessageRole.ASSISTANT, content: "Hello there" },
    ]);
    expect(state.streamingText).toBe("");
    expect(state.currentTool).toBeNull();
    expect(state.isStreaming).toBe(false);
  });

  test("applyError surfaces the detail and ends the turn", () => {
    useChatStore.setState({ streamingText: "partial", isStreaming: true });
    useChatStore.getState().applyError("boom");
    const state = useChatStore.getState();
    expect(state.error).toBe("boom");
    expect(state.isStreaming).toBe(false);
    expect(state.streamingText).toBe("");
  });

  test("applyUnavailable flags the assistant unavailable and ends the turn", () => {
    useChatStore.setState({ streamingText: "partial", isStreaming: true });
    useChatStore
      .getState()
      .applyUnavailable(
        "The assistant is currently unavailable. Please try again.",
      );
    const state = useChatStore.getState();
    expect(state.assistantUnavailable).toBe(true);
    expect(state.error).toMatch(/unavailable/i);
    expect(state.isStreaming).toBe(false);
    expect(state.streamingText).toBe("");
  });

  test("applyStart clears a prior assistantUnavailable flag", () => {
    useChatStore.setState({ assistantUnavailable: true });
    useChatStore.getState().applyStart();
    expect(useChatStore.getState().assistantUnavailable).toBe(false);
  });

  test("setConnectionState updates the badge state", () => {
    useChatStore.getState().setConnectionState(ConnectionState.CONNECTED);
    expect(useChatStore.getState().connectionState).toBe(
      ConnectionState.CONNECTED,
    );
  });
});

describe("deriveSessionLabel", () => {
  // jest runs with TZ=UTC, so the date fallback is deterministic.
  const session = { id: 1, created_at: "2026-06-11T14:02:00Z" };

  test("uses the backend-provided title (trimmed) when present", () => {
    expect(deriveSessionLabel({ ...session, title: "  hello there  " })).toBe(
      "hello there",
    );
  });

  test("falls back to the formatted created_at when there is no title", () => {
    expect(deriveSessionLabel({ ...session, title: null })).toBe(
      "2026-06-11 14:02",
    );
    expect(deriveSessionLabel(session)).toBe("2026-06-11 14:02");
  });
});

describe("useChatStore session management", () => {
  beforeEach(() => {
    useChatStore.setState(initialState);
    jest.clearAllMocks();
  });

  test("fetchSessions loads a single page", async () => {
    axios.get.mockResolvedValueOnce({
      data: { total_pages: 1, results: [{ id: 1 }, { id: 2 }] },
    });
    await useChatStore.getState().fetchSessions();
    const state = useChatStore.getState();
    expect(state.sessions).toEqual([{ id: 1 }, { id: 2 }]);
    expect(state.sessionsLoading).toBe(false);
    expect(state.sessionsError).toBeNull();
  });

  test("fetchSessions concatenates every page", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { total_pages: 2, results: [{ id: 1 }] } })
      .mockResolvedValueOnce({
        data: { total_pages: 2, results: [{ id: 2 }] },
      });
    await useChatStore.getState().fetchSessions();
    expect(useChatStore.getState().sessions).toEqual([{ id: 1 }, { id: 2 }]);
    expect(axios.get).toHaveBeenCalledTimes(2);
  });

  test("fetchSessions surfaces an error and clears loading", async () => {
    axios.get.mockRejectedValueOnce(new Error("boom"));
    await useChatStore.getState().fetchSessions();
    const state = useChatStore.getState();
    expect(state.sessionsError).toMatch(/conversations/i);
    expect(state.sessionsLoading).toBe(false);
  });

  test("switchSession loads history oldest-first and binds the session", async () => {
    axios.get.mockResolvedValueOnce({
      data: {
        total_pages: 1,
        results: [
          { id: 10, role: "user", content: "hi", timestamp: "t1" },
          { id: 11, role: "assistant", content: "yo", timestamp: "t2" },
        ],
      },
    });
    useChatStore.setState({ streamingText: "stale", currentTool: "x" });
    await useChatStore.getState().switchSession(3);
    const state = useChatStore.getState();
    expect(state.sessionId).toBe(3);
    expect(state.messages).toEqual([
      { id: 10, role: "user", content: "hi" },
      { id: 11, role: "assistant", content: "yo" },
    ]);
    expect(state.streamingText).toBe("");
    expect(state.currentTool).toBeNull();
    expect(state.historyLoading).toBe(false);
  });

  test("switchSession is a no-op for the already-active session", async () => {
    useChatStore.setState({ sessionId: 3 });
    await useChatStore.getState().switchSession(3);
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("switchSession proceeds while streaming and bumps navEpoch to abandon the turn", async () => {
    axios.get.mockResolvedValueOnce({
      data: {
        total_pages: 1,
        results: [{ id: 20, role: "user", content: "hey" }],
      },
    });
    useChatStore.setState({ isStreaming: true, sessionId: 1, navEpoch: 4 });
    await useChatStore.getState().switchSession(2);
    const state = useChatStore.getState();
    expect(state.sessionId).toBe(2);
    expect(state.messages).toEqual([{ id: 20, role: "user", content: "hey" }]);
    // the in-flight turn is abandoned: its state is reset and the epoch bumped so the WS hook's
    // watchdog (armed under epoch 4) no longer applies to the now-active session.
    expect(state.isStreaming).toBe(false);
    expect(state.navEpoch).toBe(5);
  });

  test("switchSession drops a stale result when the user switched again mid-flight", async () => {
    let resolve;
    axios.get.mockReturnValueOnce(
      new Promise((res) => {
        resolve = res;
      }),
    );
    const pending = useChatStore.getState().switchSession(1);
    // user switched to another session before the history request resolved
    useChatStore.setState({ sessionId: 2 });
    resolve({
      data: {
        total_pages: 1,
        results: [{ id: 1, role: "user", content: "old" }],
      },
    });
    await pending;
    expect(useChatStore.getState().messages).toEqual([]);
  });

  test("newChat resets to a fresh, unbound conversation and bumps navEpoch", () => {
    useChatStore.setState({
      sessionId: 7,
      messages: [{ role: "user", content: "x" }],
      streamingText: "partial",
      error: "stale",
      navEpoch: 2,
    });
    useChatStore.getState().newChat();
    const state = useChatStore.getState();
    expect(state.sessionId).toBeNull();
    expect(state.messages).toEqual([]);
    expect(state.streamingText).toBe("");
    expect(state.isStreaming).toBe(false);
    expect(state.error).toBeNull();
    expect(state.navEpoch).toBe(3);
  });

  test("newChat resets even while a turn is streaming", () => {
    useChatStore.setState({ isStreaming: true, sessionId: 7, navEpoch: 5 });
    useChatStore.getState().newChat();
    const state = useChatStore.getState();
    expect(state.sessionId).toBeNull();
    expect(state.isStreaming).toBe(false);
    expect(state.navEpoch).toBe(6);
  });

  test("deleteSession removes the active session and falls back to a fresh chat", async () => {
    axios.delete.mockResolvedValueOnce({});
    useChatStore.setState({
      sessions: [{ id: 1 }, { id: 2 }],
      sessionId: 1,
      messages: [{ role: "user", content: "x" }],
    });
    await useChatStore.getState().deleteSession(1);
    const state = useChatStore.getState();
    expect(axios.delete).toHaveBeenCalledWith(`${CHATBOT_SESSIONS_URI}/1`);
    expect(state.sessions).toEqual([{ id: 2 }]);
    expect(state.sessionId).toBeNull();
    expect(state.messages).toEqual([]);
  });

  test("deleteSession leaves the active session untouched when deleting another", async () => {
    axios.delete.mockResolvedValueOnce({});
    useChatStore.setState({
      sessions: [{ id: 1 }, { id: 2 }],
      sessionId: 2,
    });
    await useChatStore.getState().deleteSession(1);
    const state = useChatStore.getState();
    expect(state.sessions).toEqual([{ id: 2 }]);
    expect(state.sessionId).toBe(2);
  });

  test("deleteSession surfaces an error and keeps the list intact", async () => {
    axios.delete.mockRejectedValueOnce(new Error("boom"));
    useChatStore.setState({ sessions: [{ id: 1 }] });
    await useChatStore.getState().deleteSession(1);
    const state = useChatStore.getState();
    expect(state.sessionsError).toMatch(/delete/i);
    expect(state.sessions).toEqual([{ id: 1 }]);
  });
});

describe("useChatStore checkHealth", () => {
  beforeEach(() => {
    useChatStore.setState(initialState);
    jest.clearAllMocks();
  });

  test("flags unavailable and shows the detail banner", async () => {
    axios.get.mockResolvedValueOnce({
      data: { available: false, detail: "down" },
    });
    await useChatStore.getState().checkHealth();
    const state = useChatStore.getState();
    expect(state.assistantUnavailable).toBe(true);
    expect(state.error).toBe("down");
  });

  test("clears the unavailable banner when recovering", async () => {
    useChatStore.setState({ assistantUnavailable: true, error: "down" });
    axios.get.mockResolvedValueOnce({
      data: { available: true, detail: "" },
    });
    await useChatStore.getState().checkHealth();
    const state = useChatStore.getState();
    expect(state.assistantUnavailable).toBe(false);
    expect(state.error).toBeNull();
  });

  test("preserves an unrelated turn error when already available", async () => {
    useChatStore.setState({
      assistantUnavailable: false,
      error: "turn failed",
    });
    axios.get.mockResolvedValueOnce({
      data: { available: true, detail: "" },
    });
    await useChatStore.getState().checkHealth();
    expect(useChatStore.getState().error).toBe("turn failed");
  });

  test("does nothing when the health request fails", async () => {
    useChatStore.setState({ assistantUnavailable: false, error: null });
    axios.get.mockRejectedValueOnce(new Error("boom"));
    await useChatStore.getState().checkHealth();
    const state = useChatStore.getState();
    expect(state.assistantUnavailable).toBe(false);
    expect(state.error).toBeNull();
  });
});
