import React from "react";
import {
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
} from "reactstrap";
import { BsPeopleFill, BsSliders } from "react-icons/bs";
import { FiLogOut } from "react-icons/fi";
import { IoMdKey, IoMdSettings } from "react-icons/io";

import { UserBubble, DropdownNavLink } from "@certego/certego-ui";

import { useAuthStore } from "../../stores";

/**
 * @type {component}
 * @param props
 */
export default function UserMenu(props) {
  // auth store
  const user = useAuthStore(React.useCallback((s) => s.user, []));

  return (
    <UncontrolledDropdown nav inNavbar {...props}>
      <DropdownToggle nav className="text-center">
        <UserBubble size="sm" userInfo={user} />
      </DropdownToggle>
      <DropdownMenu end className="bg-dark" data-bs-popper>
        <DropdownItem text>
          logged in as <b>{`${user?.username}`}</b>
        </DropdownItem>
        <DropdownItem divider />
        {/* Django Admin Interface */}
        <DropdownNavLink to="/admin/" target="_blank">
          <IoMdSettings className="me-2" /> Django Admin Interface
        </DropdownNavLink>
        {/* Invitations */}
        <DropdownNavLink to="/me/organization">
          <BsPeopleFill className="me-2" /> Organization
        </DropdownNavLink>
        {/* API Access/Sessions */}
        <DropdownNavLink to="/me/sessions">
          <IoMdKey className="me-2" /> API Access/ Sessions
        </DropdownNavLink>
        {/* Your plugin configuration */}
        <DropdownNavLink to="/me/config">
          <BsSliders className="me-2" /> Your custom config
        </DropdownNavLink>
        <DropdownItem divider />
        <DropdownNavLink to="/logout">
          <FiLogOut className="me-2" /> Logout
        </DropdownNavLink>
      </DropdownMenu>
    </UncontrolledDropdown>
  );
}
