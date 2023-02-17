import React, { Suspense } from "react";
import { AiOutlineApi } from "react-icons/ai";
import { BsPeopleFill, BsSliders } from "react-icons/bs";
import { TiFlowChildren, TiBook } from "react-icons/ti";
import { IoIosEye } from "react-icons/io";

import {
  RouterTabs,
  FallBackLoading,
  ContentSection,
} from "@certego/certego-ui";
import { Link } from "react-router-dom";
import { Button, Col } from "reactstrap";
import { useOrganizationStore } from "../../stores";

const Analyzers = React.lazy(() => import("./utils/Analyzers"));
const Connectors = React.lazy(() => import("./utils/Connectors"));
const Visualizers = React.lazy(() => import("./utils/Visualizers"));
const Playbooks = React.lazy(() => import("./utils/Playbooks"));

const routes = [
  {
    key: "plugins-analyzers",
    location: "analyzers",
    Title: () => (
      <span>
        <AiOutlineApi />
        &nbsp;Analyzers
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Analyzers />
      </Suspense>
    ),
  },
  {
    key: "plugins-connectors",
    location: "connectors",
    Title: () => (
      <span>
        <TiFlowChildren />
        &nbsp;Connectors
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Connectors />
      </Suspense>
    ),
  },
  {
    key: "plugins-visualizers",
    location: "visualizers",
    Title: () => (
      <span>
        <IoIosEye />
        &nbsp;Visualizers
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Visualizers />
      </Suspense>
    ),
  },
  {
    key: "plugins-playbooks",
    location: "playbooks",
    Title: () => (
      <span>
        <TiBook />
        &nbsp;Playbooks
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Playbooks />
      </Suspense>
    ),
  },
];

export default function PluginsContainer() {
  console.debug("PluginsContainer rendered!");
  const {
    isUserOwner,
    organization,
    fetchAll: fetchAllOrganizations,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isUserOwner: state.isUserOwner,
        fetchAll: state.fetchAll,
        organization: state.organization,
      }),
      []
    )
  );

  // on component mount
  React.useEffect(() => {
    if (!isUserOwner) {
      fetchAllOrganizations();
    }
  }, [isUserOwner, fetchAllOrganizations]);
  const configButtons = (
    <Col className="d-flex justify-content-end">
      <ContentSection className="d-inline-flex mb-0 py-0">
        {organization?.name ? (
          <Link
            className="d-flex"
            to="/me/organization/config"
            style={{ color: "inherit", textDecoration: "inherit" }}
          >
            <Button
              size="sm"
              color="darker"
              onClick={() => null}
              className="me-2"
            >
              <BsPeopleFill className="me-2" /> Organization {organization.name}
              &apos;s plugin config
            </Button>
          </Link>
        ) : null}
        <Link
          className="d-flex"
          to="/me/config"
          style={{ color: "inherit", textDecoration: "inherit" }}
        >
          <Button size="sm" color="darker" onClick={() => null}>
            <BsSliders className="me-2" />
            Your plugin config
          </Button>
        </Link>
      </ContentSection>
    </Col>
  );
  return <RouterTabs routes={routes} extraNavComponent={configButtons} />;
}
