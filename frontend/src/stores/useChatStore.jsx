import { create } from "zustand";
import axios from "axios";
import { format } from "date-fns-tz";

import { CHATBOT_HEALTH_URI, CHATBOT_SESSIONS_URI } from "../constants/apiURLs";

/**
 * Connection states for the chat WebSocket, surfaced in the UI as a status badge.
 * The socket itself is NOT held here: per the IntelOwl convention zustand stores keep only
 * serializable state, so the WebSocket (and its timers) live in the useChatWebSocket hook via
 * refs. This store is the single source of truth for what the panel renders; the hook owns the
 * transport and calls the apply* reducers below as frames arrive.
 */
export const ConnectionState = Object.freeze({
  IDLE: "idle",
  CONNECTING: "connecting",
  CONNECTED: "connected",
  RECONNECTING: "reconnecting",
  CLOSED: "closed",
});

export const MessageRole = Object.freeze({
  USER: "user",
  ASSISTANT: "assistant",
});

// User-facing error strings for the REST session operations (same plain style as the WS hook).
const SESSIONS_LOAD_ERROR =
  "Could not load your conversations. Please try again.";
const HISTORY_LOAD_ERROR =
  "Could not load this conversation. Please try again.";
const SESSION_DELETE_ERROR =
  "Could not delete this conversation. Please try again.";

// Fetch every page of a session's messages. The backend orders by timestamp asc and returns pages
// in order, so concatenation preserves chronological (oldest-first) order. Mirrors the paginated
// download pattern in usePluginConfigurationStore.jsx.
async function fetchAllMessages(sessionId) {
  const url = `${CHATBOT_SESSIONS_URI}/${sessionId}/messages`;
  const first = await axios.get(url, { params: { page: 1 } });
  let { results } = first.data;
  if (first.data.total_pages > 1) {
    const requests = [];
    for (let page = 2; page <= first.data.total_pages; page += 1) {
      requests.push(axios.get(url, { params: { page } }));
    }
    (await Promise.all(requests)).forEach((resp) => {
      results = results.concat(resp.data.results);
    });
  }
  // ChatMessageSerializer -> { id, role, content, timestamp }; store shape is { id, role, content }.
  return results.map(({ id, role, content }) => ({ id, role, content }));
}

/**
 * Label for a session row in the list. The backend annotates each listed session with `title` (its
 * first user message, truncated); fall back to the formatted created_at for a session that has no
 * user message yet. Pure and exported so the component and tests share one source of truth.
 */
export function deriveSessionLabel(session) {
  const title = session.title?.trim();
  if (title) return title;
  return format(new Date(session.created_at), "yyyy-MM-dd HH:mm");
}

const initialTurnState = {
  // text of the assistant answer while it streams token-by-token (committed to messages on `end`)
  streamingText: "",
  // name of the tool the agent is currently running, shown as a "Running <tool>…" indicator
  currentTool: null,
  // true between sending a message and receiving `end`/`error`; disables the composer
  isStreaming: false,
};

export const useChatStore = create((set, get) => ({
  // drawer visibility (toggled from the global header, a separate component subtree)
  isOpen: false,
  // session id assigned by the server in the `ack` frame; null until the first turn binds it
  sessionId: null,
  // committed conversation: [{ id?, role, content }]
  messages: [],
  ...initialTurnState,
  connectionState: ConnectionState.IDLE,
  // last user-facing error text (cleared when a new turn starts)
  error: null,
  // true when a turn was acked but the worker produced no output (post-ack watchdog). The transport
  // is still up, so this — not connectionState — is what tells the badge the assistant itself can't
  // serve a turn right now. Cleared on the next `start` (the worker proving it is alive again).
  assistantUnavailable: false,

  // --- session list (serializable; the WS hook is untouched — these only change
  // sessionId/messages, which the hook reads live for demux and send) ---
  // [{ id, created_at, updated_at, title }] in -created_at order, as returned by the API
  sessions: [],
  sessionsLoading: false,
  sessionsError: null,
  // true while a session's messages are being (re)loaded on switch
  historyLoading: false,
  // Monotonic navigation counter, bumped whenever the user switches/opens/abandons a conversation.
  // The WS hook captures it when arming a turn's watchdog and skips the watchdog if it has moved,
  // so navigating away mid-turn can't fire a stale "unavailable"/"timeout" error onto the new view.
  navEpoch: 0,

  // --- drawer actions ---
  toggle: () => set((state) => ({ isOpen: !state.isOpen })),
  open: () => set({ isOpen: true }),
  close: () => set({ isOpen: false }),

  // --- outbound ---
  // Optimistically render the user's message and lock the composer before the server replies.
  enqueueUserMessage: (text) =>
    set((state) => ({
      messages: [...state.messages, { role: MessageRole.USER, content: text }],
      ...initialTurnState,
      isStreaming: true,
      error: null,
    })),

  // --- inbound frame reducers (called by the hook; demux/filtering happens upstream there) ---
  applyAck: (event) => set({ sessionId: event.session_id }),
  applyStart: () =>
    set({
      ...initialTurnState,
      isStreaming: true,
      error: null,
      assistantUnavailable: false,
    }),
  applyStatus: (event) => set({ currentTool: event.tool }),
  applyToken: (event) =>
    set((state) => ({ streamingText: state.streamingText + event.content })),
  applyEnd: (event) =>
    set((state) => ({
      messages: [
        ...state.messages,
        {
          id: event.message_id,
          role: MessageRole.ASSISTANT,
          content: event.content,
        },
      ],
      ...initialTurnState,
    })),
  // `detail` is the server's user-safe text, or a client-side message for the watchdog timeouts.
  // The partial streaming bubble is dropped (the server drops the turn too) but the user's message
  // stays visible so they can retry.
  applyError: (detail) => set({ ...initialTurnState, error: detail }),
  // Like applyError, but specifically for the post-ack watchdog: the turn was acked yet the worker
  // produced nothing, so the assistant is unavailable — flag the badge in addition to the banner.
  applyUnavailable: (detail) =>
    set({ ...initialTurnState, error: detail, assistantUnavailable: true }),

  // --- session management (REST) ---
  // Load the user's sessions (every page) for the list view; the queryset is user-scoped server-side.
  fetchSessions: async () => {
    set({ sessionsLoading: true, sessionsError: null });
    try {
      const first = await axios.get(CHATBOT_SESSIONS_URI, {
        params: { page: 1 },
      });
      let sessions = first.data.results;
      if (first.data.total_pages > 1) {
        const requests = [];
        for (let page = 2; page <= first.data.total_pages; page += 1) {
          requests.push(axios.get(CHATBOT_SESSIONS_URI, { params: { page } }));
        }
        (await Promise.all(requests)).forEach((resp) => {
          sessions = sessions.concat(resp.data.results);
        });
      }
      set({ sessions, sessionsLoading: false });
    } catch (error) {
      set({ sessionsError: SESSIONS_LOAD_ERROR, sessionsLoading: false });
    }
  },

  // Open an existing session: bump navEpoch (abandoning any in-flight turn — see navEpoch above and
  // the WS hook's watchdogs), reset the turn, bind sessionId (so the WS demux routes this session's
  // frames) and load its history oldest-first. Allowed mid-turn so the list stays usable while a
  // reply streams; only a no-op when the session is already active.
  switchSession: async (sessionId) => {
    const state = get();
    if (sessionId === state.sessionId) return;
    set({
      sessionId,
      messages: [],
      ...initialTurnState,
      error: null,
      historyLoading: true,
      navEpoch: state.navEpoch + 1,
    });
    try {
      const messages = await fetchAllMessages(sessionId);
      // Race guard: the user may have switched again while this request was in flight.
      if (get().sessionId !== sessionId) return;
      set({ messages, historyLoading: false });
    } catch (error) {
      if (get().sessionId !== sessionId) return;
      set({ historyLoading: false, error: HISTORY_LOAD_ERROR });
    }
  },

  // Start a fresh conversation: the next send goes with session_id=null and the server creates +
  // binds the session in its `ack`. Allowed mid-turn (bumps navEpoch to abandon the in-flight turn).
  newChat: () =>
    set((state) => ({
      sessionId: null,
      messages: [],
      ...initialTurnState,
      error: null,
      navEpoch: state.navEpoch + 1,
    })),

  // Delete a session; on success drop it from the list and, if it was the active one, fall back to a
  // fresh chat. Guarded against deleting the very session a turn is streaming into (that would race
  // the server's persistence) — deleting any other session mid-turn is fine.
  deleteSession: async (sessionId) => {
    const state = get();
    if (state.isStreaming && sessionId === state.sessionId) return;
    try {
      await axios.delete(`${CHATBOT_SESSIONS_URI}/${sessionId}`);
    } catch (error) {
      set({ sessionsError: SESSION_DELETE_ERROR });
      return;
    }
    set((current) => {
      const wasActive = current.sessionId === sessionId;
      return {
        sessions: current.sessions.filter(
          (session) => session.id !== sessionId,
        ),
        ...(wasActive
          ? {
              sessionId: null,
              messages: [],
              ...initialTurnState,
              error: null,
              navEpoch: current.navEpoch + 1,
            }
          : {}),
      };
    });
  },

  // --- connection ---
  setConnectionState: (connectionState) => set({ connectionState }),

  // Proactive availability probe, run when the drawer opens: if the chatbot worker or Ollama isn't
  // up, surface the "Unavailable" badge + a banner at once instead of after the ~20s post-ack
  // watchdog. A failed request is ignored (no false alarm); composer stays usable either way.
  checkHealth: async () => {
    let health;
    try {
      ({ data: health } = await axios.get(CHATBOT_HEALTH_URI));
    } catch (error) {
      return;
    }
    set((state) =>
      health.available
        ? {
            assistantUnavailable: false,
            // clear only the unavailable banner (on recovery), never an unrelated turn error
            error: state.assistantUnavailable ? null : state.error,
          }
        : { assistantUnavailable: true, error: health.detail },
    );
  },
}));
