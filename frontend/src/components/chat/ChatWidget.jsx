import React from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Input,
  InputGroup,
  Spinner,
} from "reactstrap";
import { MdChat, MdClose, MdSend } from "react-icons/md";

import { useAuthStore } from "../../stores/useAuthStore";
import { CHATBOT_SESSIONS_URI } from "../../constants/apiURLs";

const CHAT_WIDGET_STYLES = {
  container: {
    position: "fixed",
    bottom: "1.5rem",
    right: "1.5rem",
    zIndex: 9998,
  },
  toggleButton: {
    borderRadius: "50%",
    width: "3.5rem",
    height: "3.5rem",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxShadow: "0 2px 12px rgba(0,0,0,0.15)",
  },
  panel: {
    width: "380px",
    maxHeight: "500px",
    position: "absolute",
    bottom: "4.5rem",
    right: 0,
    boxShadow: "0 4px 24px rgba(0,0,0,0.15)",
  },
  messageList: {
    height: "350px",
    overflowY: "auto",
    padding: "0.75rem",
  },
  userMsg: {
    background: "#0d6efd",
    color: "white",
    borderRadius: "12px 12px 2px 12px",
    padding: "0.5rem 0.75rem",
    marginBottom: "0.5rem",
    maxWidth: "85%",
    marginLeft: "auto",
    wordWrap: "break-word",
  },
  assistantMsg: {
    background: "#f0f0f0",
    color: "#333",
    borderRadius: "12px 12px 12px 2px",
    padding: "0.5rem 0.75rem",
    marginBottom: "0.5rem",
    maxWidth: "85%",
    wordWrap: "break-word",
  },
  toolIndicator: {
    fontSize: "0.75rem",
    color: "#888",
    fontStyle: "italic",
    marginBottom: "0.25rem",
  },
};

const makeMsg = (role, content, extras = {}) => ({
  id: `${role}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
  role,
  content,
  ...extras,
});

export default function ChatWidget() {
  const isAuthenticated = useAuthStore(
    React.useCallback((store) => store.isAuthenticated(), []),
  );
  const [isOpen, setIsOpen] = React.useState(false);
  const [messages, setMessages] = React.useState([]);
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [sessionId, setSessionId] = React.useState(null);
  const messagesEndRef = React.useRef(null);

  // Auto-scroll to bottom when messages change.
  React.useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  if (!isAuthenticated) return null;

  const createSession = async () => {
    try {
      const resp = await fetch(CHATBOT_SESSIONS_URI, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (resp.ok) {
        const data = await resp.json();
        setSessionId(data.id);
        return data.id;
      }
    } catch {
      /* session creation failed silently */
    }
    return null;
  };

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || loading) return;

    setInput("");
    setMessages((prev) => [...prev, makeMsg("user", text)]);
    setLoading(true);

    let sid = sessionId;
    if (!sid) {
      sid = await createSession();
      if (!sid) {
        setMessages((prev) => [
          ...prev,
          makeMsg("assistant", "Failed to create chat session."),
        ]);
        setLoading(false);
        return;
      }
    }

    try {
      const resp = await fetch(`${CHATBOT_SESSIONS_URI}/${sid}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ message: text }),
      });

      if (!resp.ok) {
        throw new Error(`Server error: ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();

      // eslint-disable-next-line no-constant-condition
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        chunk
          .split("\n")
          .filter((line) => line.startsWith("data: "))
          .forEach((line) => {
            try {
              const event = JSON.parse(line.slice(6));
              if (event.type === "token") {
                setMessages((prev) => {
                  const updated = [...prev];
                  const last = updated[updated.length - 1];
                  if (last && last.role === "assistant" && last.streaming) {
                    updated[updated.length - 1] = {
                      ...last,
                      content: last.content + event.content,
                    };
                  } else {
                    updated.push(
                      makeMsg("assistant", event.content, { streaming: true }),
                    );
                  }
                  return updated;
                });
              } else if (event.type === "tool_call") {
                setMessages((prev) => [
                  ...prev,
                  makeMsg("tool", `Calling ${event.name}...`),
                ]);
              } else if (event.type === "error") {
                setMessages((prev) => [
                  ...prev,
                  makeMsg("assistant", `Error: ${event.message}`),
                ]);
              }
            } catch {
              /* ignore parse errors for incomplete chunks */
            }
          });
      }

      // Mark streaming complete.
      setMessages((prev) =>
        prev.map((msg) => (msg.streaming ? { ...msg, streaming: false } : msg)),
      );
    } catch {
      setMessages((prev) => [
        ...prev,
        makeMsg("assistant", "Connection error. Please try again."),
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  };

  return (
    <div style={CHAT_WIDGET_STYLES.container}>
      {isOpen && (
        <Card style={CHAT_WIDGET_STYLES.panel}>
          <CardHeader className="d-flex justify-content-between align-items-center py-2">
            <strong>IntelOwl Assistant</strong>
            <Button
              close
              onClick={() => setIsOpen(false)}
              aria-label="Close chat"
            >
              <MdClose />
            </Button>
          </CardHeader>
          <CardBody className="p-0">
            <div style={CHAT_WIDGET_STYLES.messageList}>
              {messages.length === 0 && (
                <p className="text-muted text-center mt-4">
                  Ask me about your threat intelligence data.
                </p>
              )}
              {messages.map((msg) => {
                if (msg.role === "tool") {
                  return (
                    <div key={msg.id} style={CHAT_WIDGET_STYLES.toolIndicator}>
                      {msg.content}
                    </div>
                  );
                }
                return (
                  <div
                    key={msg.id}
                    style={
                      msg.role === "user"
                        ? CHAT_WIDGET_STYLES.userMsg
                        : CHAT_WIDGET_STYLES.assistantMsg
                    }
                  >
                    {msg.content}
                    {msg.streaming && <Spinner size="sm" className="ms-1" />}
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>
            <div className="p-2 border-top">
              <InputGroup>
                <Input
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask about an observable..."
                  disabled={loading}
                  bsSize="sm"
                />
                <Button
                  color="primary"
                  size="sm"
                  onClick={sendMessage}
                  disabled={loading || !input.trim()}
                >
                  {loading ? <Spinner size="sm" /> : <MdSend />}
                </Button>
              </InputGroup>
            </div>
          </CardBody>
        </Card>
      )}
      <Button
        color="primary"
        style={CHAT_WIDGET_STYLES.toggleButton}
        onClick={() => setIsOpen(!isOpen)}
        title="Open chat assistant"
      >
        {isOpen ? <MdClose size={22} /> : <MdChat size={22} />}
      </Button>
    </div>
  );
}
