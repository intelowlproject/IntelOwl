import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { MembersList } from "../../../../src/components/organization/utils/MembersList";

jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state({
      loading: false,
      error: null,
      isUserOwner: false,
      noOrg: false,
      organization: {
        owner: {
          full_name: "user owner",
          joined: "2023-10-19T14:34:38.263483Z",
          username: "user_owner",
          is_admin: true,
        },
        name: "org_test",
      },
      membersCount: 3,
      members: [
        {
          full_name: "user owner",
          joined: "2023-10-19T14:34:38.263483Z",
          username: "user_owner",
          is_admin: true,
        },
        {
          full_name: "user admin",
          joined: "2023-10-19T14:34:38.263483Z",
          username: "user_admin",
          is_admin: true,
        },
        {
          full_name: "user user",
          joined: "2023-10-19T14:34:38.263483Z",
          username: "user_user",
          is_admin: false,
        },
      ],
      pendingInvitations: [],
      pluginsState: {},
      fetchAll: () => {},
      fetchOnlyBasicInfo: () => {},
      refetchMembers: () => {},
      refetchInvs: () => {},
      isUserAdmin: (username) => {
        if (["user_owner", "user_admin"].includes(username)) {
          return true;
        }
        return false;
      },
    }),
  ),
}));

describe("MembersList component", () => {
  test("MembersList - 1 owner, 1 admin, 1 user", async () => {
    const { container } = render(
      <BrowserRouter>
        <MembersList />
      </BrowserRouter>,
    );
    expect(screen.getByText("Members")).toBeInTheDocument();
    expect(screen.getByText("3 total")).toBeInTheDocument();
    // owner
    const usernameOwner = container.querySelector(
      "#memberlist-username-user_owner",
    );
    expect(usernameOwner).toBeInTheDocument();
    expect(screen.getByText("user owner")).toBeInTheDocument();
    expect(screen.getByText("(@user_owner)")).toBeInTheDocument();
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
  });
});
