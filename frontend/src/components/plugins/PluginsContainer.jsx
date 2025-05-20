import React, { Suspense } from "react";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren, TiBook } from "react-icons/ti";
import { IoIosEye } from "react-icons/io";
import { MdInput } from "react-icons/md";
import { PiGraphFill } from "react-icons/pi";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { NavLink as RRNavLink, useLocation } from "react-router-dom";
import { Button, Col, Nav, NavItem } from "reactstrap";

import { FallBackLoading } from "@certego/certego-ui";
import { useGuideContext } from "../../contexts/GuideContext";
import { PluginsTypes } from "../../constants/pluginConst";
import { PluginConfigModal } from "./PluginConfigModal";

const Analyzers = React.lazy(() => import("./tables/Analyzers"));
const Connectors = React.lazy(() => import("./tables/Connectors"));
const Pivots = React.lazy(() => import("./tables/Pivots"));
const Visualizers = React.lazy(() => import("./tables/Visualizers"));
const Ingestors = React.lazy(() => import("./tables/Ingestors"));
const Playbooks = React.lazy(() => import("./tables/Playbooks"));

export default function PluginsContainer() {
  console.debug("PluginsContainer rendered!");
  const location = useLocation();
  const pluginsPage = location?.pathname?.split("/")[2]?.slice(0, -1);
  const enableCreateButton = [
    PluginsTypes.ANALYZER,
    PluginsTypes.PIVOT,
    PluginsTypes.PLAYBOOK,
  ].includes(pluginsPage);

  const [showModalCreate, setShowModalCreate] = React.useState(false);
  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 1 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const createButton = (
    <Col className="d-flex justify-content-end">
      {enableCreateButton && (
        <Button
          id="createbutton"
          className="d-flex align-items-center"
          size="sm"
          color="darker"
          onClick={() => setShowModalCreate(true)}
        >
          <BsFillPlusCircleFill />
          &nbsp;Create {pluginsPage}
        </Button>
      )}
      {showModalCreate && (
        <PluginConfigModal
          pluginType={pluginsPage}
          toggle={setShowModalCreate}
          isOpen={showModalCreate}
        />
      )}
    </Col>
  );

  /* switch is requested or each time a section is selected everything need to be rendered again
  slowing down the performance and the UX */
  let selectedComponent;
  switch (pluginsPage) {
    case PluginsTypes.ANALYZER:
      selectedComponent = <Analyzers />;
      break;
    case PluginsTypes.CONNECTOR:
      selectedComponent = <Connectors />;
      break;
    case PluginsTypes.PIVOT:
      selectedComponent = <Pivots />;
      break;
    case PluginsTypes.VISUALIZER:
      selectedComponent = <Visualizers />;
      break;
    case PluginsTypes.INGESTOR:
      selectedComponent = <Ingestors />;
      break;
    case PluginsTypes.PLAYBOOK:
      selectedComponent = <Playbooks />;
      break;
    default:
      selectedComponent = undefined;
  }
  selectedComponent = (
    <Suspense fallback={<FallBackLoading />}>{selectedComponent}</Suspense>
  );

  return (
    <>
      <Nav className="nav-tabs">
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/analyzers">
            <span id="analyzers">
              <AiOutlineApi />
              &nbsp;Analyzers
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/connectors">
            <span id="connectors">
              <TiFlowChildren />
              &nbsp;Connectors
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/pivots">
            <span id="pivots">
              <PiGraphFill />
              &nbsp;Pivots
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/visualizers">
            <span id="visualizers">
              <IoIosEye />
              &nbsp;Visualizers
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/ingestors">
            <span id="ingestors">
              <MdInput />
              &nbsp;Ingestors
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/plugins/playbooks">
            <span id="playbooks">
              <TiBook />
              &nbsp;Playbooks
            </span>
          </RRNavLink>
        </NavItem>
        {createButton}
      </Nav>
      {selectedComponent}
    </>
  );
}
