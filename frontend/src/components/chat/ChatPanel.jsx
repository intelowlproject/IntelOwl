import React from "react";
import {
  Offcanvas,
  OffcanvasHeader,
  OffcanvasBody,
  Badge,
  Alert,
  Button,
  UncontrolledTooltip,
} from "reactstrap";
import { IoListOutline, IoArrowBack } from "react-icons/io5";
import { MdInfoOutline } from "react-icons/md";

import { useChatStore, ConnectionState } from "../../stores/useChatStore";
import { useChatWebSocket } from "./useChatWebSocket";
import { ChatMessageList } from "./ChatMessageList";
import { ChatComposer } from "./ChatComposer";
import { ChatSessionList } from "./ChatSessionList";
import { QuickActions } from "./QuickActions";
import { ChatActionConfirm } from "./ChatActionConfirm";

// Connection-state badge shown in the drawer header.
const CONNECTION_BADGE = {
  [ConnectionState.IDLE]: { color: "secondary", label: "Idle" },
  [ConnectionState.CONNECTING]: { color: "warning", label: "Connecting" },
  [ConnectionState.CONNECTED]: { color: "success", label: "Connected" },
  [ConnectionState.RECONNECTING]: { color: "warning", label: "Reconnecting" },
  [ConnectionState.CLOSED]: { color: "danger", label: "Disconnected" },
};

// Shown instead of the green "Connected" badge when the socket is up but the chatbot worker isn't
// serving turns (see useChatStore.assistantUnavailable).
const UNAVAILABLE_BADGE = { color: "warning", label: "Unavailable" };

// One-line description behind the header info icon, mirroring the MdInfoOutline + tooltip pattern
// used elsewhere in IntelOwl (e.g. TLPSelectInput).
const ASSISTANT_INFO_TEXT =
  "Privacy-preserving assistant: ask about your IntelOwl data in natural language. " +
  "All inference runs locally via Ollama — nothing is sent to external services.";

/**
 * The chat drawer. Mounted once, globally (AppMain Layout), so it overlays every authenticated
 * page and survives open/close; the WebSocket lives in useChatWebSocket, which lazily connects the
 * first time the drawer opens. `backdrop={false}` keeps the rest of the app usable while open.
 */
export function ChatPanel() {
  const isOpen = useChatStore((state) => state.isOpen);
  const close = useChatStore((state) => state.close);
  const connectionState = useChatStore((state) => state.connectionState);
  const isStreaming = useChatStore((state) => state.isStreaming);
  const assistantUnavailable = useChatStore(
    (state) => state.assistantUnavailable,
  );
  const error = useChatStore((state) => state.error);

  // Disable the composer and quick actions while a turn is streaming or the socket is not
  // connected. ChatComposer computes this internally; QuickActions receives it as a prop.
  const inputDisabled =
    isStreaming || connectionState !== ConnectionState.CONNECTED;
  const checkHealth = useChatStore((state) => state.checkHealth);
  const { sendMessage } = useChatWebSocket();

  // Master-detail mode: "conversation" (messages + composer) or "sessions" (the session list).
  // Local state — purely presentational and not shared with the distant header, unlike `isOpen`.
  const [view, setView] = React.useState("conversation");
  // Always reopen the drawer on the conversation view.
  React.useEffect(() => {
    if (!isOpen) setView("conversation");
  }, [isOpen]);

  // Proactively probe availability each time the drawer opens, so a down chatbot worker / Ollama is
  // obvious immediately instead of after the post-ack watchdog.
  React.useEffect(() => {
    if (isOpen) checkHealth();
  }, [isOpen, checkHealth]);

  // The badge reflects assistant availability, not just transport: a connected socket whose worker
  // isn't serving turns (assistantUnavailable) must not keep reading green "Connected".
  const badge =
    assistantUnavailable && connectionState === ConnectionState.CONNECTED
      ? UNAVAILABLE_BADGE
      : CONNECTION_BADGE[connectionState] ??
        CONNECTION_BADGE[ConnectionState.IDLE];

  return (
    <Offcanvas
      direction="end"
      isOpen={isOpen}
      toggle={close}
      backdrop={false}
      scrollable
      id="chat-panel"
    >
      <OffcanvasHeader toggle={close}>
        {view === "conversation" ? (
          <Button
            color="link"
            className="p-0 me-2 text-reset"
            aria-label="Show conversations"
            onClick={() => setView("sessions")}
          >
            <IoListOutline />
          </Button>
        ) : (
          <Button
            color="link"
            className="p-0 me-2 text-reset"
            aria-label="Back to conversation"
            onClick={() => setView("conversation")}
          >
            <IoArrowBack />
          </Button>
        )}
        Assistant
        <MdInfoOutline id="chat-assistant-info" className="ms-1" />
        <UncontrolledTooltip
          target="chat-assistant-info"
          placement="bottom"
          fade={false}
          autohide={false}
          innerClassName="p-2 text-start"
        >
          {ASSISTANT_INFO_TEXT}
        </UncontrolledTooltip>
        <Badge color={badge.color} className="ms-2">
          {badge.label}
        </Badge>
      </OffcanvasHeader>
      <OffcanvasBody className="d-flex flex-column p-0">
        {error && (
          <Alert color="danger" className="m-2">
            {error}
          </Alert>
        )}
        {view === "sessions" ? (
          <ChatSessionList onSessionChosen={() => setView("conversation")} />
        ) : (
          <>
            <ChatMessageList />
            <ChatActionConfirm />
            <QuickActions onSend={sendMessage} disabled={inputDisabled} />
            <ChatComposer onSend={sendMessage} />
          </>
        )}
      </OffcanvasBody>
    </Offcanvas>
  );
}
