import React from "react";
import axios from "axios";
import {
  Nav,
  Navbar,
  NavItem,
  Collapse,
  NavbarBrand,
  NavbarToggler,
  Button,
  UncontrolledPopover,
} from "reactstrap";
import { NavLink as RRNavLink, useLocation } from "react-router-dom";
import { AiOutlineDashboard } from "react-icons/ai";
import { SiHackaday } from "react-icons/si";
import { MdHome, MdShare } from "react-icons/md";
import {
  RiFileListFill,
  RiPlugFill,
  RiBookReadFill,
  RiGuideLine,
} from "react-icons/ri";
import { FaTwitter, FaGithub, FaGoogle } from "react-icons/fa";

// lib
import { NavLink, AxiosLoadingBar } from "@certego/certego-ui";

// constants
import {
  INTELOWL_DOCS_URL,
  PUBLIC_URL,
  VERSION,
  INTELOWL_TWITTER_ACCOUNT,
} from "../constants/environment";

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
      <Button id="social-button" size="sm" className="mx-2 btn-info">
        <>
          <MdShare />
          <span className="ms-1">Social</span>
        </>
      </Button>
      <UncontrolledPopover
        target="social-button"
        placement="bottom"
        trigger="hover"
        delay={{ show: 0, hide: 500 }}
        popperClassName="p-2 bg-dark"
      >
        <div className="d-flex-center flex-column">
          <div className="d-flex my-1">
            <a
              href={`https://twitter.com/${INTELOWL_TWITTER_ACCOUNT}`}
              target="_blank"
              rel="noopener noreferrer"
              className="ms-md-2 twitter-follow-button"
            >
              <FaTwitter /> Follow @{INTELOWL_TWITTER_ACCOUNT}
            </a>
          </div>
          <div>
            <a
              href="https://github.com/intelowlproject"
              target="_blank"
              rel="noopener noreferrer"
              className="ms-md-2 btn-social my-1"
            >
              {" "}
              <FaGithub /> Connect on Github{" "}
            </a>
          </div>
          <div>
            <Button
              href="https://www.honeynet.org/gsoc/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-xs ms-md-2 btn-social my-1"
            >
              <FaGoogle /> Honeynet on GSOC
            </Button>
          </div>
        </div>
      </UncontrolledPopover>
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
          <small className="text-accent">{VERSION}</small>
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
              <NavItem>
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
