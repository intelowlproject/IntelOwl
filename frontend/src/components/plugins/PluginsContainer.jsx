import React, { Suspense } from "react";
import { AiOutlineApi } from "react-icons/ai";
import { TiFlowChildren, TiBook } from "react-icons/ti";
import { IoIosEye } from "react-icons/io";
import { MdInput } from "react-icons/md";
import { PiGraphFill } from "react-icons/pi";

import {
  RouterTabs,
  FallBackLoading,
  // ContentSection,
} from "@certego/certego-ui";
// import { Button, Col } from "reactstrap";
import { useGuideContext } from "../../contexts/GuideContext";

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

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 1 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <RouterTabs routes={routes} />;
}
