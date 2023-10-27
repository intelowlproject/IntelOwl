import React from "react";
import { Col, Fade, ButtonGroup } from "reactstrap";
import { SiMinutemailer } from "react-icons/si";
import { MdEdit, MdDelete } from "react-icons/md";

import { ContentSection, DateHoverable, IconButton } from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { deleteInvitation } from "../orgApi";
import { InviteButton } from "./InviteButton";

export function PendingInvitationsList() {
  // consume store
  const { pendingInvitations, refetchInvs, isUserOwner } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pendingInvitations: state.pendingInvitations,
        refetchInvs: state.refetchInvs,
        isUserOwner: state.isUserOwner,
      }),
      [],
    ),
  );

  // state
  const [showActions, setShowActions] = React.useState(false);

  // callbacks
  const deleteInvitationCb = async (invId, username) => {
    await deleteInvitation(invId, username);
    setTimeout(refetchInvs, 100);
  };

  return (
    <Fade>
      <SiMinutemailer size="16px" className="float-start text-secondary" />
      <ContentSection className="bg-body border border-dark">
        {/* Header */}
        <section className="h3 d-flex justify-content-between align-items-end flex-column flex-sm-row">
          <div>
            Pending Invitations&nbsp;
            <small className="text-muted">
              {pendingInvitations?.length} total
            </small>
          </div>
          <div>
            {isUserOwner && (
              <ButtonGroup>
                <InviteButton onCreate={refetchInvs} />
                <IconButton
                  id="pendinginvitelist-showactions-btn"
                  size="sm"
                  color="tertiary"
                  title="toggle actions visibility"
                  Icon={MdEdit}
                  onClick={() => setShowActions((s) => !s)}
                  // active state
                  outline={!showActions}
                />
              </ButtonGroup>
            )}
          </div>
        </section>
        <hr />
        {/* List */}
        <section>
          {pendingInvitations?.length ? (
            <ol>
              {pendingInvitations.map(({ id, user, created_at: invitedAt }) => (
                <li key={`pendinvinvlist-${id}`}>
                  <div className="d-flex flex-wrap">
                    <Col sm={6}>{user?.username}</Col>
                    <Col sm={5}>
                      <DateHoverable
                        date={invitedAt}
                        format="PPP"
                        className="text-secondary user-select-none"
                        title="Invite sent date"
                      />
                    </Col>
                    <Col sm={1}>
                      {showActions && (
                        <MdDelete
                          className="text-danger pointer small"
                          title="delete invitation"
                          onClick={() => deleteInvitationCb(id, user?.username)}
                        />
                      )}
                    </Col>
                  </div>
                </li>
              ))}
            </ol>
          ) : null}
        </section>
      </ContentSection>
    </Fade>
  );
}
