import React from "react";
import {
  Dropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem
} from "reactstrap";
import { NavLink as RRNavLink } from "react-router-dom";
import { BsPeopleFill } from "react-icons/bs";
import { IoMdKey } from "react-icons/io";

import { UserBubble } from "@certego/certego-ui";

import { useAuthStore } from "../../stores";

/**
 * @type {component}
 * @param props
 */
export default function UserMenu(props) {
  // state
  const [isDropdownOpen, setDropdownOpen] = React.useState(false);

  // auth store
  const user = useAuthStore(React.useCallback((s) => s.user, []));

  return (
    <Dropdown
      isOpen={isDropdownOpen}
      toggle={() => setDropdownOpen((ps) => !ps)}
      nav
      inNavbar
      {...props}
    >
      <DropdownToggle nav className="text-center">
        <UserBubble size="sm" userInfo={user} />
      </DropdownToggle>
      <DropdownMenu right className="bg-dark">
        <DropdownItem
          text
        >{`${user?.full_name} (${user.username})`}</DropdownItem>
        <DropdownItem divider />
        {/* Invitations */}
        <DropdownItem
          tag={RRNavLink}
          exact
          to="/me/organization"
          activeClassName="nav-link-active"
        >
          <BsPeopleFill className="mr-2" />
          Organization
        </DropdownItem>
        {/* API Access/Sessions */}
        <DropdownItem
          tag={RRNavLink}
          exact
          to="/me/sessions"
          activeClassName="nav-link-active"
        >
          <IoMdKey className="mr-2" />
          API Access/ Sessions
        </DropdownItem>
        <DropdownItem divider />
        <DropdownItem tag={RRNavLink} exact to="/logout" isActive={() => false}>
          Logout
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
}
