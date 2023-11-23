import React from "react";
import { Col, Fade } from "reactstrap";
import { SiMinutemailer } from "react-icons/si";
import { MdDelete } from "react-icons/md";

import { ContentSection, DateHoverable } from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { useAuthStore } from "../../../stores/useAuthStore";
import { deleteInvitation } from "../orgApi";
import { InviteButton } from "./InviteButton";

export function PendingInvitationsList() {
  // consume store
  const [user] = useAuthStore((state) => [state.user]);

  const { pendingInvitations, refetchInvs, isUserAdmin } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pendingInvitations: state.pendingInvitations,
        refetchInvs: state.refetchInvs,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  // callbacks
  const deleteInvitationCb = async (invId, username) => {
    await deleteInvitation(invId, username);
    setTimeout(refetchInvs, 100);
  };

  return (
    <Fade>
      <SiMinutemailer size="16px" className="float-start text-secondary" />
      <ContentSection
        id="organization-pending-invitations"
        className="bg-body border border-dark"
      >
        {/* Header */}
        <section className="h3 d-flex justify-content-between align-items-end flex-column flex-sm-row">
          <div>
            Pending Invitations&nbsp;
            <small className="text-muted">
              {pendingInvitations?.length} total
            </small>
          </div>
          <div>
            {isUserAdmin(user.username) && (
              <InviteButton onCreate={refetchInvs} />
            )}
          </div>
        </section>
        <hr />
        {/* List */}
        <section>
          {pendingInvitations?.length ? (
            <ol>
              {pendingInvitations.map(
                ({ id, user: invitedUser, created_at: invitedAt }) => (
                  <li
                    key={`pendinvinvlist-${id}`}
                    className="border-bottom border-dark py-1"
                  >
                    <div className="d-flex flex-wrap">
                      <Col sm={5}>{invitedUser?.username}</Col>
                      <Col sm={5}>
                        <DateHoverable
                          value={invitedAt}
                          format="do MMMM yyyy"
                          className="text-secondary user-select-none"
                          title="Invite sent date"
                        />
                      </Col>
                      <Col sm={2} className="text-end">
                        {isUserAdmin(user.username) && (
                          <MdDelete
                            className="text-danger pointer small"
                            title="delete invitation"
                            onClick={() =>
                              deleteInvitationCb(id, invitedUser?.username)
                            }
                          />
                        )}
                      </Col>
                    </div>
                  </li>
                ),
              )}
            </ol>
          ) : null}
        </section>
      </ContentSection>
    </Fade>
  );
}
