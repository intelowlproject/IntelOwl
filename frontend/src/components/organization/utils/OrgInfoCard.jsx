import React from "react";
import { Alert } from "reactstrap";

import { DateHoverable } from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";

export function OrgInfoCard() {
  // consume store
  const {
    organization: { name, owner, establishedAt },
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
        isUserOwner: state.isUserOwner,
      }),
      [],
    ),
  );

  return (
    <Alert color="secondary">
      {/* Header */}
      <section className="text-info h3">{name}</section>
      {/* Box */}
      <section className="border border-dark p-3">
        {/* Owner */}
        <div>
          <small className="text-dark me-2">
            <b>Owner:</b>
          </small>
          <span className="text-info">
            {owner?.full_name} <small>(@{owner?.username})</small>
          </span>
        </div>
        {/* Established */}
        <div>
          <small className="text-dark me-2">
            <b>Established:</b>
          </small>
          {establishedAt && (
            <DateHoverable
              id="org-created_at"
              fromNow
              value={establishedAt}
              format="do MMMM yyyy"
              className="text-info"
            />
          )}
        </div>
      </section>
    </Alert>
  );
}
