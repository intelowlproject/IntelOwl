import React from "react";
import axios from "axios";
import {
  Nav,
  Navbar,
  NavItem,
  Collapse,
  NavbarBrand,
  NavbarToggler,
} from "reactstrap";
import { NavLink as RRNavLink, useLocation } from "react-router-dom";
import { AiOutlineDashboard } from "react-icons/ai";
import { SiHackaday } from "react-icons/si";
import { MdHome } from "react-icons/md";
import {
  RiFileListFill,
  RiPlugFill,
  RiBookReadFill,
  RiGuideLine,
} from "react-icons/ri";

// lib
import { NavLink, AxiosLoadingBar } from "@certego/certego-ui";

// constants
import { INTELOWL_DOCS_URL, PUBLIC_URL } from "../constants/environment";

// local
import UserMenu from "./widgets/UserMenu";
import NotificationPopoverButton from "../components/jobs/notification/NotificationPopoverButton";
import { useAuthStore } from "../stores/useAuthStore";
import { useGuideContext } from "../contexts/GuideContext";

const authLinks = (
  <>
    <NavItem>
      <NavLink className="d-flex-start-center" end to="/dashboard">
        <AiOutlineDashboard />
        <span className="ms-1" id="dashboard-title">
          Dashboard
        </span>
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
  <>
    <NavItem>
      <RRNavLink id="login-btn" className="btn btn-sm btn-info" end to="/login">
        Login
      </RRNavLink>
    </NavItem>
    <NavItem className="ms-lg-2">
      <RRNavLink
        id="register-btn"
        className="btn btn-sm btn-accent-2"
        end
        to="/register"
      >
        Register
      </RRNavLink>
    </NavItem>
  </>
);

// eslint-disable-next-line react/prop-types
function RightLinks({ handleClickStart, isAuthenticated }) {
  const location = useLocation();
  const isRootPath = location.pathname === "/";
  return (
    <>
      {isRootPath && isAuthenticated && (
        <NavItem>
          <button
            type="button"
            className="d-flex-start-center btn text-gray"
            onClick={handleClickStart}
          >
            <RiGuideLine />
            <span className="ms-1">Guide</span>
          </button>
        </NavItem>
      )}
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
    </>
  );
}

function AppHeader() {
  console.debug("AppHeader rendered!");

  const { setGuideState } = useGuideContext();

  const handleClickStart = () => {
    setGuideState({ run: true, tourActive: true });
  };

  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  // auth store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated(), []),
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
        <NavbarToggler onClick={() => setIsOpen(!isOpen)} />
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
            <RightLinks
              handleClickStart={handleClickStart}
              isAuthenticated={isAuthenticated}
            />
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
