import React from "react";
import { Row, Col, Fade, ButtonGroup, Badge } from "reactstrap";
import { MdDelete } from "react-icons/md";
import { FaUserFriends, FaUserEdit, FaUserMinus } from "react-icons/fa";

import {
  ContentSection,
  DateHoverable,
  IconButton,
  confirm,
} from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { useAuthStore } from "../../../stores/useAuthStore";
import {
  deleteOrganization,
  removeMemberFromOrg,
  leaveOrganization,
} from "../orgApi";

export function MembersList() {
  // consume store
  const [user] = useAuthStore((state) => [state.user]);
  const {
    organization: { owner, name: orgName },
    members,
    membersCount,
    fetchAll,
    refetchMembers,
    isUserOwner,
    isUserAdmin,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
        members: state.members,
        membersCount: state.membersCount,
        fetchAll: state.fetchAll,
        refetchMembers: state.refetchMembers,
        isUserOwner: state.isUserOwner,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  // state
  const [showActions, setShowActions] = React.useState(false);

  // memo
  const sortedMembers = React.useMemo(
    () =>
      members?.length ? [...members].sort((a, b) => a.joined - b.joined) : [],
    [members],
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
    [refetchMembers],
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
            <ButtonGroup>
              {isUserOwner ? (
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
              ) : (
                <IconButton
                  id="memberslist-leaveorg-btn"
                  size="sm"
                  outline
                  color="danger"
                  className="border border-tertiary"
                  title="Leave Organization"
                  Icon={FaUserMinus}
                  onClick={leaveOrganizationCb}
                />
              )}
              {isUserAdmin(user.username) && (
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
              )}
            </ButtonGroup>
          </div>
        </section>
        <hr />
        {/* List */}
        <section>
          {sortedMembers?.length && (
            <ol>
              {sortedMembers.map(
                ({
                  username,
                  full_name: fullName,
                  joined,
                  is_admin: isAdmin,
                }) => (
                  <li key={`memberlist-${username}`}>
                    <Row>
                      <Col sm={5} title="Name and Username">
                        {fullName}&nbsp;
                        <span
                          id={`memberlist-username-${username}`}
                          className="text-muted"
                        >
                          (@{username})
                        </span>
                      </Col>
                      <Col sm={5} title="Joining Date">
                        <DateHoverable
                          value={joined}
                          format="do MMMM yyyy"
                          className="text-secondary user-select-none"
                        />
                      </Col>
                      <Col sm={2} className="text-end">
                        {showActions &&
                          owner.username !== username &&
                          (!isUserAdmin(username) ||
                            (isUserAdmin(username) && isUserOwner)) && (
                            <FaUserMinus
                              className="text-danger pointer small"
                              title="remove member"
                              onClick={() => removeMemberCb(username)}
                            />
                          )}
                        {owner?.username === username && (
                          <Badge
                            id={`memberlist-badge-owner-${username}`}
                            color="info"
                          >
                            Owner
                          </Badge>
                        )}
                        {owner?.username !== username && isAdmin && (
                          <Badge
                            id={`memberlist-badge-admin-${username}`}
                            color="info"
                          >
                            Admin
                          </Badge>
                        )}
                      </Col>
                    </Row>
                  </li>
                ),
              )}
            </ol>
          )}
        </section>
      </ContentSection>
    </Fade>
  );
}
