import React from "react";
import "@testing-library/jest-dom";
import userEvent from "@testing-library/user-event";
import axios from "axios";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { BASE_URI_ORG } from "../../../../src/constants/apiURLs";
import { MembersList } from "../../../../src/components/organization/utils/MembersList";
import { mockedUseOrganizationStoreOwner } from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore", () => ({
  useOrganizationStore: jest.fn((state) =>
    state(mockedUseOrganizationStoreOwner),
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
  });

  test("MembersList - promote/remove user as admin", async () => {
    axios.post.mockImplementation((url) => {
      console.debug(url);
      switch (url) {
        case `${BASE_URI_ORG}/remove_admin`:
          return Promise.resolve({ status: 204 });
        case `${BASE_URI_ORG}/promote_admin`:
          return Promise.resolve({ status: 200 });
        default:
          return Promise.reject(new Error("Error"));
      }
    });

    const { container } = render(
      <BrowserRouter>
        <MembersList />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

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

    // promote user as admin
    await user.click(userAdminActionsButton);
    // setTimeout(() => {
    //   expect(adminUserBadge).toBeInTheDocument();
    // }, 100);

    // remove admin
    await user.click(adminActionsButton);
    // setTimeout(() => {
    //   expect(adminBadge).toBeNull();
    // }, 100);
  });
});
