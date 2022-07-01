import React from "react";
import { Alert, Row, Col, Fade, ButtonGroup, Badge } from "reactstrap";
import { SiMinutemailer } from "react-icons/si";
import { MdEdit, MdDelete } from "react-icons/md";
import { FaUserFriends, FaUserEdit, FaUserMinus } from "react-icons/fa";

import {
  ContentSection,
  DateHoverable,
  IconButton,
  confirm,
} from "@certego/certego-ui";

import { useOrganizationStore } from "../../../../stores";
import {
  deleteInvitation,
  deleteOrganization,
  removeMemberFromOrg,
  leaveOrganization,
} from "../api";
import InviteButton from "./InviteButton";

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
      []
    )
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

export function MembersList() {
  // consume store
  const {
    organization: { owner, name: orgName },
    members,
    membersCount,
    fetchAll,
    refetchMembers,
    isUserOwner,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
        members: state.members,
        membersCount: state.membersCount,
        fetchAll: state.fetchAll,
        refetchMembers: state.refetchMembers,
        isUserOwner: state.isUserOwner,
      }),
      []
    )
  );

  // state
  const [showActions, setShowActions] = React.useState(false);

  // memo
  const sortedMembers = React.useMemo(
    () =>
      members?.length ? [...members].sort((a, b) => a.joined - b.joined) : [],
    [members]
  );

  // callbacks
  const removeMemberCb = React.useCallback(
    async (username) => {
      const answer = await confirm({
        message: (
          <p>
            User <u>@{username}</u> will be removed from your organization and
            will no longer have access to the <b>rules</b> and{" "}
            <b>submissions</b>
            &nbsp;of your organization members.
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
        await removeMemberFromOrg(username);
        setTimeout(refetchMembers, 100);
      }
    },
    [refetchMembers]
  );
  const leaveOrganizationCb = React.useCallback(async () => {
    const answer = await confirm({
      message: (
        <p>
          You will be removed from the <u>{orgName}</u> organization and will no
          longer have access to the <b>rules</b> and <b>submissions</b>
          &nbsp;of the organization members.
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
      await leaveOrganization(orgName);
      setTimeout(fetchAll, 100);
    }
  }, [orgName, fetchAll]);
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

  // UI
  return (
    <Fade>
      <FaUserFriends size="16px" className="float-start text-secondary" />
      <ContentSection className="bg-body border border-dark">
        {/* Header */}
        <section className="h3 d-flex justify-content-between align-items-end flex-column flex-sm-row">
          <div>
            Members&nbsp;
            <small className="text-muted">{membersCount} total</small>
          </div>
          <div>
            {isUserOwner ? (
              <ButtonGroup>
                <IconButton
                  id="deleteorg-btn"
                  size="sm"
                  outline
                  color="danger"
                  className="border border-tertiary"
                  title="Delete Organization"
                  Icon={MdDelete}
                  onClick={deleteOrganizationCb}
                />
                <IconButton
                  id="memberslist-showactions-btn"
                  size="sm"
                  color="tertiary"
                  title="toggle actions visibility"
                  Icon={FaUserEdit}
                  onClick={() => setShowActions((s) => !s)}
                  // active state
                  outline={!showActions}
                />
              </ButtonGroup>
            ) : (
              <IconButton
                id="memberslist-leaveorg-btn"
                size="sm"
                outline
                color="danger"
                title="Leave Organization"
                Icon={FaUserMinus}
                onClick={leaveOrganizationCb}
              />
            )}
          </div>
        </section>
        <hr />
        {/* List */}
        <section>
          {sortedMembers?.length && (
            <ol>
              {sortedMembers.map(
                ({ username, full_name: fullName, joined }) => (
                  <li key={`memberlist-${username}`}>
                    <Row>
                      <Col sm={5} title="Name and Username">
                        {fullName}&nbsp;
                        <span className="text-muted">(@{username})</span>
                      </Col>
                      <Col sm={5} title="Joining Date">
                        <DateHoverable
                          date={joined}
                          format="PPP"
                          className="text-secondary user-select-none"
                        />
                      </Col>
                      <Col sm={2} className="text-end">
                        {owner?.username !== username ? (
                          showActions && (
                            <FaUserMinus
                              className="text-danger pointer small"
                              title="remove member"
                              onClick={() => removeMemberCb(username)}
                            />
                          )
                        ) : (
                          <Badge color="info">admin</Badge>
                        )}
                      </Col>
                    </Row>
                  </li>
                )
              )}
            </ol>
          )}
        </section>
      </ContentSection>
    </Fade>
  );
}

export function PendingInvitationsList() {
  // consume store
  const { pendingInvitations, refetchInvs, isUserOwner } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pendingInvitations: state.pendingInvitations,
        refetchInvs: state.refetchInvs,
        isUserOwner: state.isUserOwner,
      }),
      []
    )
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
