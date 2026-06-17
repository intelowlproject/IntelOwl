import React from "react";
import { Card, CardBody, Button } from "reactstrap";

import { useChatStore } from "../../stores/useChatStore";

/**
 * Confirmation card for an analyze_observable preview. The agent can only propose an analysis
 * (it returns a plan + pending_id); the actual launch happens here, on an explicit user click,
 * via the backend confirm endpoint — so the model can never start an analysis on its own.
 * Renders nothing unless the store holds a pending action.
 */
export function ChatActionConfirm() {
  const pendingAction = useChatStore((state) => state.pendingAction);
  const confirmPendingAction = useChatStore(
    (state) => state.confirmPendingAction,
  );
  const cancelPendingAction = useChatStore(
    (state) => state.cancelPendingAction,
  );
  const isStreaming = useChatStore((state) => state.isStreaming);
  const [submitting, setSubmitting] = React.useState(false);

  if (!pendingAction) return null;
  const { plan } = pendingAction;
  // The backend `action_required` plan always carries these lists (AnalysisPlanSerializer), but
  // default to [] so a malformed/partial frame degrades to an empty row instead of crashing render.
  const analyzers = plan.analyzers ?? [];
  const connectors = plan.connectors ?? [];
  const skipped = plan.skipped ?? [];

  const onConfirm = async () => {
    setSubmitting(true);
    try {
      await confirmPendingAction();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card className="m-2 border-warning" id="chat-action-confirm">
      <CardBody className="p-2 small">
        <div className="fw-bold mb-1">Start this analysis?</div>
        <div>
          Observable: {plan.observable_name} ({plan.classification})
        </div>
        <div>TLP: {plan.tlp}</div>
        {plan.playbook && <div>Playbook: {plan.playbook}</div>}
        <div>Analyzers: {analyzers.join(", ") || "default"}</div>
        {connectors.length > 0 && (
          <div>Connectors: {connectors.join(", ")}</div>
        )}
        {skipped.length > 0 && (
          <div className="text-muted">Skipped: {skipped.join(", ")}</div>
        )}
        <div className="d-flex gap-2 mt-2">
          {/* Confirm is also gated on isStreaming (can't launch mid-turn); Cancel deliberately is
              NOT — dismissing a stale card must always work, even while a reply streams. */}
          <Button
            color="primary"
            size="sm"
            disabled={submitting || isStreaming}
            onClick={onConfirm}
          >
            Confirm
          </Button>
          <Button
            color="outline-secondary"
            size="sm"
            disabled={submitting}
            onClick={cancelPendingAction}
          >
            Cancel
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
