import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import MyOrgPage from "../../../src/components/organization/MyOrgPage";
import { mockedUseOrganizationStoreOwner } from "../../mock";

jest.mock("../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreOwner),
  ),
}));

// current user must be equal to org owner
jest.mock("../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) =>
    state({
      user: {
        username: "user_owner",
        full_name: "user owner",
        first_name: "user",
        last_name: "owner",
        email: "test@google.com",
      },
    }),
  ),
}));

describe("Org page component", () => {
  test("org page - owner view", async () => {
    const { container } = render(
      <BrowserRouter>
        <MyOrgPage />
      </BrowserRouter>,
    );
    // info card
    const orgInfoCard = container.querySelector("#organization-info-card");
    expect(orgInfoCard).toBeInTheDocument();
    expect(screen.getByText("org_test")).toBeInTheDocument();
    expect(screen.getAllByText("user owner")[0]).toBeInTheDocument();
    expect(screen.getAllByText("(@user_owner)")[0]).toBeInTheDocument();
    expect(screen.getByText("Established:")).toBeInTheDocument();
    expect(screen.getByText("18th October 2023")).toBeInTheDocument();
    const deleteOrgButton = container.querySelector("#deleteorg-btn");
    expect(deleteOrgButton).toBeInTheDocument();

    // members sections
    const membersSection = container.querySelector("#organization-members");
    expect(membersSection).toBeInTheDocument();
    expect(screen.getByText("Members")).toBeInTheDocument();
    expect(screen.getByText("3 total")).toBeInTheDocument();
    // owner
    const usernameOwner = container.querySelector(
      "#memberlist-username-user_owner",
    );
    expect(usernameOwner).toBeInTheDocument();
    expect(screen.getAllByText("user owner")[1]).toBeInTheDocument();
    expect(screen.getAllByText("(@user_owner)")[1]).toBeInTheDocument();
    const ownerBadge = container.querySelector(
      "#memberlist-badge-owner-user_owner",
    );
    expect(ownerBadge).toBeInTheDocument();
    // admin
    const usernameAdmin = container.querySelector(
      "#memberlist-username-user_admin",
    );
    expect(usernameAdmin).toBeInTheDocument();
    expect(screen.getByText("user admin")).toBeInTheDocument();
    expect(screen.getByText("(@user_admin)")).toBeInTheDocument();
    const adminBadge = container.querySelector(
      "#memberlist-badge-admin-user_admin",
    );
    expect(adminBadge).toBeInTheDocument();
    const adminRemoveMemberButton = container.querySelector(
      "#memberslist-removemember-btn-user_admin",
    );
    expect(adminRemoveMemberButton).toBeInTheDocument();
    const adminActionsButton = container.querySelector(
      "#memberslist-adminactions-btn-user_admin",
    );
    expect(adminActionsButton).toBeInTheDocument();
    // user
    const usernameUser = container.querySelector(
      "#memberlist-username-user_user",
    );
    expect(usernameUser).toBeInTheDocument();
    expect(screen.getByText("user user")).toBeInTheDocument();
    expect(screen.getByText("(@user_user)")).toBeInTheDocument();
    const ownerUserBadge = container.querySelector(
      "#memberlist-badge-owner-user_user",
    );
    expect(ownerUserBadge).toBeNull();
    const adminUserBadge = container.querySelector(
      "#memberlist-badge-admin-user_user",
    );
    expect(adminUserBadge).toBeNull();
    const userRemoveMemberButton = container.querySelector(
      "#memberslist-removemember-btn-user_user",
    );
    expect(userRemoveMemberButton).toBeInTheDocument();
    const userAdminActionsButton = container.querySelector(
      "#memberslist-adminactions-btn-user_user",
    );
    expect(userAdminActionsButton).toBeInTheDocument();

    // pending invitations sections
    const pendingInvitationsSection = container.querySelector(
      "#organization-pending-invitations",
    );
    expect(pendingInvitationsSection).toBeInTheDocument();
    expect(screen.getByText("Pending Invitations")).toBeInTheDocument();
    const invitationIcon = container.querySelector("#invitationform-icon");
    expect(invitationIcon).toBeInTheDocument();
  });
});
