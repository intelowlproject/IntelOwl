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
import { MdShare } from "react-icons/md";
import {
  RiPlugFill,
  RiBookReadFill,
  RiGuideLine,
  RiTwitterXFill,
} from "react-icons/ri";
import { FaGithub, FaGoogle, FaLinkedin } from "react-icons/fa";
import { IoSearch } from "react-icons/io5";
import { TbReport, TbReportSearch, TbDatabaseSearch } from "react-icons/tb";

// lib
import { AxiosLoadingBar } from "@certego/certego-ui";

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
import { useOrganizationStore } from "../stores/useOrganizationStore";

const guestLinks = (
  <>
    <NavItem>
      <RRNavLink
        id="login-btn"
        className="btn btn-sm btn-primary"
        end
        to="/login"
      >
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
function AuthLinks() {
  return (
    <>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/dashboard">
          <AiOutlineDashboard />
          <span className="ms-1" id="dashboard-title">
            Dashboard
          </span>
        </RRNavLink>
      </NavItem>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/analyzables">
          <TbDatabaseSearch />
          <span className="ms-1">Analyzables</span>
        </RRNavLink>
      </NavItem>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/history">
          <TbReport />
          <span className="ms-1">History</span>
        </RRNavLink>
      </NavItem>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/search">
          <TbReportSearch />
          <span className="ms-1">Reports</span>
        </RRNavLink>
      </NavItem>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/plugins">
          <RiPlugFill />
          <span className="ms-1">Plugins</span>
        </RRNavLink>
      </NavItem>
      <NavItem>
        <RRNavLink className="d-flex-start-center nav-link" to="/scan">
          <IoSearch />
          <span className="ms-1">Scan</span>
        </RRNavLink>
      </NavItem>
    </>
  );
}

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
      <Button
        id="social-button"
        size="sm"
        className="mx-2 btn-accent d-flex align-items-center"
      >
        <>
          <MdShare />
          <span className="ms-1">Social</span>
        </>
      </Button>
      <UncontrolledPopover
        target="social-button"
        placement="bottom"
        trigger="click"
        popperClassName="p-2 bg-dark"
      >
        <div className="d-flex-center flex-column">
          <div className="d-flex my-1">
            <a
              href={`https://twitter.com/${INTELOWL_TWITTER_ACCOUNT}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-social d-flex align-items-center"
            >
              <RiTwitterXFill className="text-info me-1" /> Follow @
              {INTELOWL_TWITTER_ACCOUNT}
            </a>
          </div>
          <div>
            <a
              href="https://github.com/intelowlproject"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-social my-1 d-flex align-items-center"
            >
              <FaGithub className="me-1" /> Connect on Github{" "}
            </a>
          </div>
          <div>
            <a
              href="https://www.linkedin.com/company/intelowl"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-social my-1 d-flex align-items-center"
            >
              <FaLinkedin className="me-1" /> IntelOwl on LinkedIn{" "}
            </a>
          </div>
          <div>
            <a
              href="https://www.honeynet.org/gsoc/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-social my-1 d-flex align-items-center"
            >
              <FaGoogle className="text-accent me-1" /> Honeynet on GSOC{" "}
            </a>
          </div>
          <div>
            <a
              href="https://gsoc-slack.honeynet.org/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-social my-1 d-flex align-items-center"
            >
              <img
                className="px-1"
                title="Honeynet"
                src={`${PUBLIC_URL}/icons/honeynet.ico`}
                alt="honeynet"
                width="24px"
                height="16px"
              />
              Honeynet Slack Chat{" "}
            </a>
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
    React.useCallback((state) => state.isAuthenticated(), []),
  );

  // organization store
  const isInOrganization = useOrganizationStore(
    React.useCallback((state) => state.isInOrganization, []),
  );

  return (
    <header className="sticky-top">
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
          <small className="text-accent" style={{ fontFamily: "Pacifico" }}>
            {VERSION}
          </small>
        </NavbarBrand>
        <NavbarToggler onClick={() => setIsOpen(!isOpen)} />
        <Collapse navbar isOpen={isOpen}>
          {/* Navbar Left Side */}
          <Nav navbar id="navbar-left-side">
            {isAuthenticated && (
              <AuthLinks isInOrganization={isInOrganization} />
            )}
          </Nav>
          {/* Navbar Right Side */}
          <Nav
            navbar
            className="ms-auto d-flex align-items-center"
            id="navbar-right-side"
          >
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
