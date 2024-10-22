import React, { Suspense } from "react";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren, TiBook } from "react-icons/ti";
import { IoIosEye } from "react-icons/io";
import { MdInput } from "react-icons/md";
import { PiGraphFill } from "react-icons/pi";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { useLocation } from "react-router-dom";
import { Button, Col } from "reactstrap";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";
import { useGuideContext } from "../../contexts/GuideContext";
import { PlaybookConfigForm } from "./forms/PlaybookConfigForm";
import { PivotConfigForm } from "./forms/PivotConfigForm";
import { AnalyzerConfigForm } from "./forms/AnalyzerConfigForm";
import { PluginsTypes } from "../../constants/pluginConst";

const Analyzers = React.lazy(() => import("./types/Analyzers"));
const Connectors = React.lazy(() => import("./types/Connectors"));
const Pivots = React.lazy(() => import("./types/Pivots"));
const Visualizers = React.lazy(() => import("./types/Visualizers"));
const Ingestors = React.lazy(() => import("./types/Ingestors"));
const Playbooks = React.lazy(() => import("./types/Playbooks"));

const routes = [
  {
    key: "plugins-analyzers",
    location: "analyzers",
    Title: () => (
      <span id="Analyzers">
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
      <span id="Connectors">
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
    key: "plugins-pivots",
    location: "pivots",
    Title: () => (
      <span id="Pivots">
        <PiGraphFill />
        &nbsp;Pivots
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Pivots />
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
    key: "plugins-ingestors",
    location: "ingestors",
    Title: () => (
      <span>
        <MdInput />
        &nbsp;Ingestors
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <Ingestors />
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
  const location = useLocation();
  const pluginsPage = location?.pathname.split("/")[2];
  const enableCreateButton = [
    `${PluginsTypes.ANALYZER}s`,
    `${PluginsTypes.PIVOT}s`,
    `${PluginsTypes.PLAYBOOK}s`,
  ].includes(pluginsPage);

  const [showModalCreatePlaybook, setShowModalCreatePlaybook] =
    React.useState(false);
  const [showModalCreatePivot, setShowModalCreatePivot] = React.useState(false);
  const [showModalCreateAnalyzer, setShowModalCreateAnalyzer] =
    React.useState(false);

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 1 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onClick = async () => {
    // open modal for create playbook
    if (pluginsPage === `${PluginsTypes.PLAYBOOK}s`) {
      setShowModalCreatePlaybook(true);
    }
    // open modal for create pivot
    if (pluginsPage === `${PluginsTypes.PIVOT}s`) {
      setShowModalCreatePivot(true);
    }
    // open modal for create analyzer
    if (pluginsPage === `${PluginsTypes.ANALYZER}s`) {
      setShowModalCreateAnalyzer(true);
    }
    return null;
  };

  const createButton = (
    <Col className="d-flex justify-content-end">
      {enableCreateButton && (
        <Button
          id="createbutton"
          className="d-flex align-items-center"
          size="sm"
          color="darker"
          onClick={onClick}
        >
          <BsFillPlusCircleFill />
          &nbsp;Create {pluginsPage}
        </Button>
      )}
      {showModalCreatePlaybook && (
        <PlaybookConfigForm
          toggle={setShowModalCreatePlaybook}
          isOpen={showModalCreatePlaybook}
        />
      )}
      {showModalCreatePivot && (
        <PivotConfigForm
          toggle={setShowModalCreatePivot}
          isOpen={showModalCreatePivot}
        />
      )}
      {showModalCreateAnalyzer && (
        <AnalyzerConfigForm
          toggle={setShowModalCreateAnalyzer}
          isOpen={showModalCreateAnalyzer}
        />
      )}
    </Col>
  );

  return <RouterTabs routes={routes} extraNavComponent={createButton} />;
}
