import React from "react";
import {
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
  Badge,
} from "reactstrap";
import { BsPeopleFill, BsSliders } from "react-icons/bs";
import { FiLogOut } from "react-icons/fi";
import { IoMdKey, IoMdSettings } from "react-icons/io";
import { RiLockPasswordFill } from "react-icons/ri";

import { UserBubble, DropdownNavLink } from "@certego/certego-ui";

import { useAuthStore } from "../../stores/useAuthStore";
import { useOrganizationStore } from "../../stores/useOrganizationStore";

/**
 * @type {component}
 * @param props
 */
export default function UserMenu(props) {
  // auth store
  const user = useAuthStore(React.useCallback((state) => state.user, []));
  const {
    organization: { owner },
    isUserAdmin,
    fetchAll,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
        fetchAll: state.fetchAll,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  console.debug(`UserMenu - user: ${JSON.stringify(user)}`);

  React.useEffect(() => {
    fetchAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <UncontrolledDropdown nav inNavbar {...props}>
      <DropdownToggle nav className="text-center">
        <UserBubble size="sm" userInfo={user} />
      </DropdownToggle>
      <DropdownMenu end className="bg-dark" data-bs-popper>
        <DropdownItem text>
          logged in as <b>{user?.username}</b>
        </DropdownItem>
        <DropdownItem divider />
        {/* Django Admin Interface */}
        {user?.is_staff && (
          <DropdownNavLink to="/admin/" target="_blank">
            <IoMdSettings className="me-2" /> Django Admin Interface
          </DropdownNavLink>
        )}
        {/* Invitations */}
        <DropdownNavLink to="/me/organization">
          <BsPeopleFill className="me-2" /> Organization
          {owner?.username === user.username && (
            <Badge className="mx-3" color="info">
              Owner
            </Badge>
          )}
          {owner?.username !== user.username && isUserAdmin(user.username) && (
            <Badge className="mx-3" color="info">
              Admin
            </Badge>
          )}
        </DropdownNavLink>
        {/* API Access/Sessions */}
        <DropdownNavLink to="/me/api">
          <IoMdKey className="me-2" /> API Access
        </DropdownNavLink>
        {/* Change Password */}
        <DropdownNavLink to="/change-password">
          <RiLockPasswordFill className="me-2" /> Change password
        </DropdownNavLink>
        {/* Your plugin configuration */}
        <DropdownNavLink to="/me/config">
          <BsSliders className="me-2" /> Your plugin configuration
        </DropdownNavLink>
        <DropdownItem divider />
        <DropdownNavLink to="/logout">
          <FiLogOut className="me-2" /> Logout
        </DropdownNavLink>
      </DropdownMenu>
    </UncontrolledDropdown>
  );
}
