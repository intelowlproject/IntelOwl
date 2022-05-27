import React from "react";
import axios from "axios";
import {
  Nav,
  Navbar,
  NavItem,
  Collapse,
  NavbarBrand,
  NavbarToggler
} from "reactstrap";
import { NavLink as RRNavLink } from "react-router-dom";
import { GoDashboard } from "react-icons/go";
import { SiHackaday } from "react-icons/si";
import { MdHome } from "react-icons/md";
import { RiFileListFill, RiPlugFill, RiBookReadFill } from "react-icons/ri";

// lib
import { NavLink, AxiosLoadingBar } from "@certego/certego-ui";

// constants
import { INTELOWL_DOCS_URL, PUBLIC_URL } from "../constants/environment";

// local
import UserMenu from "./widgets/UserMenu";
import NotificationPopoverButton from "../components/misc/notification/NotificationPopoverButton";
import { useAuthStore } from "../stores";

const authLinks = (
  <>
    <NavItem>
      <NavLink className="d-flex-start-center" end to="/dashboard">
        <GoDashboard />
        <span className="ms-1">Dashboard</span>
      </NavLink>
    </NavItem>
    <NavItem>
      <NavLink className="d-flex-start-center" end to="/jobs">
        <RiFileListFill />
        <span className="ms-1">Jobs</span>
      </NavLink>
    </NavItem>
    <NavItem>
      <NavLink className="d-flex-start-center" to="/plugins">
        <RiPlugFill />
        <span className="ms-1">Plugins</span>
      </NavLink>
    </NavItem>
    <NavItem>
      <NavLink className="d-flex-start-center" end to="/scan">
        <SiHackaday />
        <span className="ms-1">Scan</span>
      </NavLink>
    </NavItem>
  </>
);

const guestLinks = (
  <NavItem>
    <RRNavLink
      id="login-btn"
      className="btn btn-sm btn-accent-2"
      end
      to="/login"
    >
      Login
    </RRNavLink>
  </NavItem>
);

const rightLinks = (
  <NavItem>
    <a
      className="d-flex-start-center btn text-gray"
      href={INTELOWL_DOCS_URL}
      target="_blank"
      rel="noopener noreferrer"
    >
      <RiBookReadFill />
      <span className="ms-1">Docs</span>
    </a>
  </NavItem>
);

function AppHeader() {
  console.debug("AppHeader rendered!");

  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  // auth store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated(), [])
  );

  return (
    <header className="fixed-top">
      {/* top loading bar */}
      <AxiosLoadingBar axiosInstance={axios} />
      {/* nav bar */}
      <Navbar dark expand="lg">
        <NavbarBrand tag={RRNavLink} to="/">
          <img
            src={`${PUBLIC_URL}/logo-negative-reduced.png`}
            width="128"
            alt="IntelOwl logo"
          />
        </NavbarBrand>
        <NavbarToggler onClick={(e) => setIsOpen(!isOpen)} />
        <Collapse navbar isOpen={isOpen}>
          {/* Navbar Left Side */}
          <Nav navbar>
            <NavItem>
              <NavLink className="d-flex-start-center" end to="/">
                <MdHome />
                <span className="ms-1">Home</span>
              </NavLink>
            </NavItem>
            {isAuthenticated && authLinks}
          </Nav>
          {/* Navbar Right Side */}
          <Nav navbar className="ms-auto d-flex align-items-center">
            {rightLinks}
            {/* Notifications Popover */}
            {isAuthenticated && (
              <NavItem className="me-lg-3">
                <NotificationPopoverButton />
              </NavItem>
            )}
            {!isAuthenticated ? guestLinks : <UserMenu />}
          </Nav>
        </Collapse>
      </Navbar>
    </header>
  );
}

export default AppHeader;
