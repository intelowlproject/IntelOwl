import React from "react";

import { WEBSOCKET_CHAT_URI } from "../../constants/apiURLs";
import { useChatStore, ConnectionState } from "../../stores/useChatStore";

// Inbound frame types — mirror ChatEventType in api_app/chatbot_manager/events.py.
const ChatEventType = Object.freeze({
  ACK: "ack",
  START: "start",
  STATUS: "status",
  TOKEN: "token",
  END: "end",
  ERROR: "error",
  ACTION_REQUIRED: "action_required",
});

// Normal WebSocket close code: a clean close must NOT trigger a reconnect.
const NORMAL_CLOSURE = 1000;

// Capped exponential backoff for the reconnect (chat is long-lived, unlike the Job socket which
// closes on the final status). Give up after a few attempts and surface a CLOSED badge.
const RECONNECT_BASE_MS = 1000;
const RECONNECT_CAP_MS = 30000;
const MAX_RECONNECT_ATTEMPTS = 5;

// Post-ack watchdog: the consumer sends `ack` synchronously *before* enqueuing the Celery turn
// (process_chat_message.delay), so the ack arrives even when the chatbot worker is down — then no
// `start`/`end`/`error` ever follows and the composer would stay locked forever. If no `start`
// lands within this window after an `ack`, give up and unlock the composer.
const POST_ACK_TIMEOUT_MS = 20000;

// Max-turn watchdog: bounds `start` -> no `end`. Set just above the server soft_time_limit (300s)
// so the server's own timeout normally wins; this only fires when the socket drops mid-turn (the
// group `end` is sent into the dead window and is not buffered) or the worker is hard-killed
// (SIGKILL never reaches the soft limit, so no `chat.error` is emitted).
const MAX_TURN_TIMEOUT_MS = 310000;

// Client-side error texts (mirror the user-safe strings in ChatErrorDetail).
const WORKER_UNAVAILABLE_TEXT =
  "The assistant is currently unavailable. Please try again.";
const TURN_TIMEOUT_TEXT =
  "The assistant took too long to respond. Please try again.";

function buildChatWebSocketUrl() {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  // Trailing slash matters: the backend route is `ws/chat/`. context_url carries the page the
  // user is on (captured server-side for later context injection).
  const contextUrl = encodeURIComponent(window.location.href);
  return `${scheme}://${window.location.host}/${WEBSOCKET_CHAT_URI}/?context_url=${contextUrl}`;
}

/**
 * Owns the chat WebSocket and bridges it to useChatStore.
 *
 * The socket, the reconnect timer and the two per-turn watchdog timers all live in refs (never in
 * the store) so re-renders don't recreate them — the same pattern JobResult uses for the job
 * socket. The hook lazily connects the first time the drawer opens and then keeps the socket alive
 * across open/close; it only tears down on unmount. Returns `sendMessage` for the composer.
 */
export function useChatWebSocket() {
  const isOpen = useChatStore((state) => state.isOpen);

  const websocket = React.useRef(null);
  const reconnectTimer = React.useRef(null);
  const reconnectAttempts = React.useRef(0);
  const postAckTimer = React.useRef(null);
  const maxTurnTimer = React.useRef(null);
  // Set on unmount so the onclose handler does not schedule a reconnect during teardown.
  const isUnmounting = React.useRef(false);

  const clearTurnTimers = React.useCallback(() => {
    if (postAckTimer.current) {
      clearTimeout(postAckTimer.current);
      postAckTimer.current = null;
    }
    if (maxTurnTimer.current) {
      clearTimeout(maxTurnTimer.current);
      maxTurnTimer.current = null;
    }
  }, []);

  const dispatchEvent = React.useCallback(
    (event) => {
      const store = useChatStore.getState();
      const activeSession = store.sessionId;
      switch (event.type) {
        case ChatEventType.ACK:
          // `ack` reaches only this socket; bind the (possibly new) session id, then arm the
          // post-ack watchdog until the agent proves it is alive by emitting `start`.
          store.applyAck(event);
          if (postAckTimer.current) clearTimeout(postAckTimer.current);
          {
            const epoch = store.navEpoch;
            postAckTimer.current = setTimeout(() => {
              // Check the epoch BEFORE clearing the ref: if the user navigated away this turn is
              // abandoned and the ref may already hold a newer turn's timer — nulling it here would
              // orphan that timer past clearTurnTimers and fire a stale error on the new turn.
              if (useChatStore.getState().navEpoch !== epoch) return;
              postAckTimer.current = null;
              // worker-down signal: flip the availability badge, not just the error banner
              useChatStore.getState().applyUnavailable(WORKER_UNAVAILABLE_TEXT);
            }, POST_ACK_TIMEOUT_MS);
          }
          break;
        case ChatEventType.START:
          // Strict demux: `start`/`status`/`token`/`end` fan out to every tab of this user, so a
          // tab must drop frames that belong to another session. A fresh tab has sessionId === null
          // and therefore matches nothing.
          if (event.session_id !== activeSession) return;
          // The agent answered: cancel the post-ack watchdog and arm the max-turn one.
          if (postAckTimer.current) {
            clearTimeout(postAckTimer.current);
            postAckTimer.current = null;
          }
          {
            const epoch = store.navEpoch;
            maxTurnTimer.current = setTimeout(() => {
              // See the post-ack watchdog: epoch-check first so a stale callback can't null a ref
              // that a newer overlapping turn has since taken over.
              if (useChatStore.getState().navEpoch !== epoch) return;
              maxTurnTimer.current = null;
              useChatStore.getState().applyError(TURN_TIMEOUT_TEXT);
            }, MAX_TURN_TIMEOUT_MS);
          }
          store.applyStart();
          break;
        case ChatEventType.STATUS:
          if (event.session_id !== activeSession) return;
          store.applyStatus(event);
          break;
        case ChatEventType.TOKEN:
          if (event.session_id !== activeSession) return;
          store.applyToken(event);
          break;
        case ChatEventType.END:
          if (event.session_id !== activeSession) return;
          clearTurnTimers();
          store.applyEnd(event);
          break;
        case ChatEventType.ACTION_REQUIRED:
          // A tool previewed an analysis the user must confirm. Demuxed like the streaming frames so
          // another tab's preview never raises this tab's card; it does NOT end the turn (prose still
          // streams), so the turn watchdogs are left untouched.
          if (event.session_id !== activeSession) return;
          store.applyActionRequired(event);
          break;
        case ChatEventType.ERROR:
          // Looser guard than the streaming frames: the consumer's *direct* errors arrive only on
          // this socket with session_id === null (INVALID_MESSAGE), so the null branch must pass;
          // the agent errors arrive via the group with the active session id. A different non-null
          // session id belongs to another tab and is ignored.
          if (event.session_id != null && event.session_id !== activeSession)
            return;
          clearTurnTimers();
          store.applyError(event.detail);
          break;
        default:
          break;
      }
    },
    [clearTurnTimers],
  );

  const connect = React.useCallback(() => {
    if (websocket.current) return;
    const { setConnectionState } = useChatStore.getState();
    setConnectionState(ConnectionState.CONNECTING);
    const url = buildChatWebSocketUrl();
    console.debug(`connect to chat websocket: ${url}`);
    const socket = new WebSocket(url);
    websocket.current = socket;

    socket.onopen = () => {
      reconnectAttempts.current = 0;
      useChatStore.getState().setConnectionState(ConnectionState.CONNECTED);
    };
    socket.onmessage = (wsData) => {
      let event;
      try {
        event = JSON.parse(wsData.data);
      } catch (parseError) {
        console.error("chat ws: unparsable frame", parseError);
        return;
      }
      dispatchEvent(event);
    };
    socket.onerror = (wsError) => {
      console.error("chat ws error", wsError);
    };
    socket.onclose = (closeEvent) => {
      websocket.current = null;
      // Terminal closes (teardown, clean close, reconnect budget exhausted) end the turn for good:
      // drop the watchdogs so a stale timer can't fire an error minutes later onto a dead socket.
      if (isUnmounting.current || closeEvent.code === NORMAL_CLOSURE) {
        clearTurnTimers();
        useChatStore.getState().setConnectionState(ConnectionState.CLOSED);
        return;
      }
      if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
        clearTurnTimers();
        useChatStore.getState().setConnectionState(ConnectionState.CLOSED);
        return;
      }
      // Abnormal mid-turn drop: keep the turn watchdogs armed across the reconnect. The in-flight
      // turn's `start`/`end` lands in the dead window and is never replayed to the new socket (group
      // frames aren't buffered), so the watchdog is the only thing that unlocks the composer here —
      // clearing it on close would strand `isStreaming` forever.
      const delay = Math.min(
        RECONNECT_BASE_MS * 2 ** reconnectAttempts.current,
        RECONNECT_CAP_MS,
      );
      reconnectAttempts.current += 1;
      useChatStore.getState().setConnectionState(ConnectionState.RECONNECTING);
      reconnectTimer.current = setTimeout(connect, delay);
    };
  }, [dispatchEvent, clearTurnTimers]);

  // Lazy connect on first open; keep the socket alive afterwards (no idle socket for users who
  // never open the chat). Teardown happens only on unmount.
  React.useEffect(() => {
    if (isOpen && !websocket.current) {
      connect();
    }
  }, [isOpen, connect]);

  React.useEffect(
    () => () => {
      isUnmounting.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      clearTurnTimers();
      if (websocket.current) {
        websocket.current.close(NORMAL_CLOSURE);
        websocket.current = null;
      }
    },
    [clearTurnTimers],
  );

  const sendMessage = React.useCallback((text) => {
    const trimmed = text.trim();
    const socket = websocket.current;
    if (!trimmed || !socket || socket.readyState !== WebSocket.OPEN) return;
    const store = useChatStore.getState();
    store.enqueueUserMessage(trimmed);
    socket.send(
      JSON.stringify({ message: trimmed, session_id: store.sessionId }),
    );
  }, []);

  return { sendMessage };
}
