import React from "react";
import Joyride from "react-joyride";
import { Outlet, useNavigate } from "react-router-dom";
import { useMount } from "react-use";
import { useGuideContext } from "../../contexts/GuideContext";

export default function GuideWrapper() {
  const { guideState, setGuideState } = useGuideContext();
  const navigate = useNavigate();

  const steps = [
    {
      target: "#home__bgImg",
      content: (
        <div id="guidebox">
          <h3>Guide</h3>
          <p>
            Welcome to IntelOwls Guide for First Time Visitors!
            For further
            questions you could either check out our <a href="https://intelowl.readthedocs.io/en/latest/">docs</a> or reach us
            out on <a href="https://www.honeynet.org/gsoc/">the official IntelOwl slack channel</a>
          </p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Dashboard_title",
      content: (
        <div id="guidebox">
          <h3>Dashboard</h3>
          <p>See previous job details here with charts and more</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Dashboard_timepicker",
      content: (
        <div id="guidebox">
          <h3>Filter</h3>
          <p>Filter by time to get details about previous jobs</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Analyzers",
      content: (
        <div id="guidebox">
          <h3>Plugins</h3>
          <p>
            Analyzers are the most important plugins in IntelOwl. They allow to
            perform data extraction on the observables and/or files that you
            would like to analyze.
          </p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#pluginconfigbutton",
      content: (
        <div id="guidebox">
          <h3>Plugin Configurations</h3>
          <p>Write up your own plugin configs</p>
          <p>
            Note: Your plugin configuration overrides your organizations
            configuration (if any).
          </p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#scanpage",
      content: (
        <div id="guidebox">
          <h3>Scan Page</h3>
          <p>
            You could get started with analyzing various observabls with just
            three steps{" "}
          </p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#selectobservable",
      content: (
        <div id="guidebox">
          <p>Select/Add Observables </p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#selectplugins",
      content: (
        <div id="guidebox">
          <p>Select from different plugins(Analyzers/Playbooks/Ingestors)</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#startScan",
      content: (
        <div id="guidebox">
          <h3>Click to Start the Scan</h3>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#jobsHistory",
      content: (
        <div id="guidebox">
          <h3>Job History</h3>
          <p>
            Here you could see the list of all previous jobs and expand over the
            details through clicking that particular job from the table
          </p>
        </div>
      ),
      disableBeacon: true,
    },
  ];

  useMount(() => {
    setGuideState({
      steps,
    });
  });

  const handleCallback = (data) => {
    const { action, index, _lifecycle, type } = data;

    switch (index) {
      case 0:
        if (type === "step:after") {
          setGuideState({ run: false, stepIndex: 1 });
          navigate("/dashboard");
        }
        break;
      case 1:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 2 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 2:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 3 });
            navigate("/plugins");
            setGuideState({ run: true, stepIndex: 2 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 3:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 4 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 4:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: false, stepIndex: 5 });
            navigate("/scan");
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 5:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 6 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 6:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 7 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 7:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 8 });
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 8:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 9 });
            navigate("/jobs");
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      case 9:
        if (type === "step:after") {
          if (action === "close") {
            setGuideState({ run: true, stepIndex: 10 });
            navigate("/");
          } else {
            setGuideState({ run: false, stepIndex: 0 });
            navigate("/");
          }
        }
        break;
      default:
        setGuideState({ run: false, stepIndex: 0 });
        navigate("/");
        break;
    }
  };

  return (
    <>
      <Outlet />
      <Joyride
        callback={handleCallback}
        run={guideState.run}
        hideCloseButton
        locale={{
          // NOTE: this fixes the button behaviours for react-joyride
          close: "Next",
          back: "Close",
        }}
        stepIndex={guideState.stepIndex}
        steps={guideState.steps}
        styles={{
          options: {
            arrowColor: "#000",
            backgroundColor: "#001D24",
            primaryColor: "#5592AA",
            textColor: "#fff",
          },
        }}
      />
    </>
  );
}
