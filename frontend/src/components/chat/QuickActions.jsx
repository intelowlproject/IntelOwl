import React from "react";
import PropTypes from "prop-types";
import { Button } from "reactstrap";

// URL patterns mirror derive_page_context in api_app/chatbot_manager/agent/context.py.
// When the frontend Routes.jsx paths change (/jobs/:id or /investigation/:id), these
// regexes must be updated in lockstep with context.py. Both sides have coupling tests:
//   - backend: tests/api_app/chatbot_manager/test_context.py
//   - frontend: tests/components/chat/QuickActions.test.jsx
export const JOB_DETAIL_RE = /^\/jobs\/(\d+)(?:\/|$)/;
export const INVESTIGATION_DETAIL_RE = /^\/investigation\/(\d+)(?:\/|$)/;

const JOB_ACTIONS = [
  { label: "Summarize this job", message: "Summarize job #{id}" },
  { label: "Which plugins ran?", message: "Which plugins ran on job #{id}?" },
  { label: "Show job details", message: "Show me the details of job #{id}" },
  { label: "Evaluate results", message: "Evaluate the results of job #{id}" },
];

const INVESTIGATION_ACTIONS = [
  {
    label: "Summarize this investigation",
    message: "Summarize investigation #{id}",
  },
  {
    label: "Show investigation tree",
    message: "Show the tree for investigation #{id}",
  },
  {
    label: "Analyze this investigation",
    message: "What can you tell me about investigation #{id}?",
  },
];

const GENERIC_ACTIONS = [
  { label: "Show my recent jobs", message: "Show my recent jobs" },
  {
    label: "List my investigations",
    message: "List my investigations",
  },
];

/**
 * Derive entity info from the current page URL, mirroring derive_page_context in the
 * backend. Returns { type, id } for a recognised entity detail page, or null for any
 * other page (dashboard, plugins, history, etc.).
 */
function deriveEntity() {
  const { pathname } = window.location;
  const jobMatch = pathname.match(JOB_DETAIL_RE);
  if (jobMatch) return { type: "job", id: jobMatch[1] };
  const invMatch = pathname.match(INVESTIGATION_DETAIL_RE);
  if (invMatch) return { type: "investigation", id: invMatch[1] };
  return null;
}

/**
 * Context-aware quick-action chips. On job and investigation detail pages the user
 * gets entity-specific suggestions; everywhere else they see generic "show me" actions.
 * Each chip auto-sends its message on click (populate + send, no second step).
 */
export function QuickActions({ onSend, disabled }) {
  const entity = deriveEntity();
  let actions;

  if (!entity) {
    actions = GENERIC_ACTIONS;
  } else if (entity.type === "job") {
    actions = JOB_ACTIONS;
  } else {
    actions = INVESTIGATION_ACTIONS;
  }

  const handleClick = (message) => {
    const resolved = entity ? message.replace("{id}", entity.id) : message;
    onSend(resolved);
  };

  return (
    <div className="d-flex flex-wrap gap-1 p-2" id="quick-actions">
      {actions.map((action) => (
        <Button
          key={action.label}
          color="outline-secondary"
          size="sm"
          disabled={disabled}
          onClick={() => handleClick(action.message)}
        >
          {action.label}
        </Button>
      ))}
    </div>
  );
}

QuickActions.propTypes = {
  onSend: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
};

QuickActions.defaultProps = {
  disabled: false,
};
