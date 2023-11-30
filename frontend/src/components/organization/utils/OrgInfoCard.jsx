import React from "react";
import { MdDelete } from "react-icons/md";

import {
  ContentSection,
  DateHoverable,
  IconButton,
  confirm,
} from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { deleteOrganization } from "../orgApi";

export function OrgInfoCard() {
  // consume store
  const {
    organization: { name, owner, establishedAt, name: orgName },
    isUserOwner,
    fetchAll,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
        isUserOwner: state.isUserOwner,
        fetchAll: state.fetchAll,
      }),
      [],
    ),
  );

  const deleteOrganizationCb = React.useCallback(async () => {
    const answer = await confirm({
      message: (
        <p>
          Organization &quot;<u>{orgName}</u>&quot; will be deleted along with
          every membership (user memberships, not user accounts) and invitations
          too.
          <br />
          <span className="text-warning">
            Are you sure you wish to proceed?
          </span>
        </p>
      ),
      confirmText: "Yes",
      confirmColor: "primary",
      cancelColor: "link text-gray",
    });
    if (answer) {
      await deleteOrganization(orgName);
      setTimeout(fetchAll, 100);
    }
  }, [orgName, fetchAll]);

  return (
    <ContentSection
      id="organization-info-card"
      color="secondary"
      className="d-flex align-items-center justify-content-between"
    >
      <div className="d-flex align-items-center">
        {/* Header */}
        <h3 className="me-5 mb-0">{name}</h3>
        {/* Owner */}
        <div>
          <small className="text-info me-2">
            <b>Owner:</b>
          </small>
          <span>
            {owner?.full_name} <small>(@{owner?.username})</small>
          </span>
        </div>
        {/* Established */}
        <div className="mx-5">
          <small className="text-info me-2">
            <b>Established:</b>
          </small>
          {establishedAt && (
            <DateHoverable
              id="org-created_at"
              value={establishedAt}
              format="do MMMM yyyy"
            />
          )}
        </div>
      </div>
      {isUserOwner && (
        <IconButton
          id="deleteorg-btn"
          size="sm"
          outline
          color="danger"
          className="border border-tertiary d-flex-end"
          title="Delete Organization"
          Icon={MdDelete}
          onClick={deleteOrganizationCb}
        />
      )}
    </ContentSection>
  );
}
