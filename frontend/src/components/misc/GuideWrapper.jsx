import React from "react";
// eslint-disable-next-line no-unused-vars
import Joyride, { CallBackProps } from "react-joyride";
import { Outlet, useNavigate } from "react-router-dom";
import { useMount } from "react-use";
import { useGuideContext } from "../../contexts/GuideContext";

export default function GuideWrapper() {
  const {
    setState,
    state,
  } = useGuideContext();
  const navigate = useNavigate();

  const steps = [
    {
      target: "#home__bgImg",
      content: (
        <div id="guidebox">
          <h3>Guide</h3>
          <p>Welcome to IntelOwl Guide!</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Dashboard_title",
      content: (
        <div id="guidebox">
          <h3>Dashboard</h3>
          <p>See previous job details here</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Dashboard_timepicker",
      content: (
        <div id="guidebox">
          <h3>Filter</h3>
          <p>Filter by time here</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#Analyzers", 
      content: (
        <div id="guidebox">
          <h3>PLugins</h3>
          <p>different plugins here</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#pluginconfigbutton",
      content: (
        <div id="guidebox">
          <h3>plugin config</h3>
          <p>config up your own plugins</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#scanpage",
      content: (
        <div id="guidebox">
          <h3>this is scan page</h3>
          <p>do this</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#selectobservable",
      content: (
        <div id="guidebox">
          
          <p>select observable</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#selectplugins",
      content: (
        <div id="guidebox">
          <p>select plugins</p>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#startScan",
      content: (
        <div id="guidebox">
          <h3>start scan</h3>
        </div>
      ),
      disableBeacon: true,
    },
    {
      target: "#jobsHistory",
      content: (
        <div id="guidebox">
          <h3>history</h3>
          <p>kjabdjk</p>
        </div>
      ),
      disableBeacon: true,
    },
  ];

  useMount(() => {
    setState({
      steps,
    });
  });

  const handleCallback = (data) => {
    const { _action, index, _lifecycle, type } = data;

    if (type === "step:after" && index === 0) {
      setState({ run: false, stepIndex: 1 });
      navigate("/dashboard");
    }
    if (type === "step:after" && index === 1) {
      setState({ run: true, stepIndex: 2 });
    }
    if (type === "step:after" && index === 2) {
      setState({ run: true, stepIndex: 3  });
      navigate("/plugins");
    }
    if (type === "step:after" && index === 3) {
      setState({ run: true, stepIndex: 4  });
    }
    if (type === "step:after" && index === 4) {
      setState({ run: false, stepIndex: 5  });
      navigate("/scan");
    }
    if (type === "step:after" && index === 5) {
      setState({ run: true, stepIndex: 6  });
    }
    if (type === "step:after" && index === 6) {
      setState({ run: true, stepIndex: 7  });
    }
    if (type === "step:after" && index === 7) {
      setState({ run: true, stepIndex: 8  });
    }
    if (type === "step:after" && index === 8) {
      setState({ run: true, stepIndex: 9  });
      navigate("/jobs");
    }
    if (type === "step:after" && index === 9) {
      setState({ run: true, stepIndex: 10  });
      navigate("/");
    }
  };

  return (
    <>
      <Outlet />
      <Joyride
        callback={handleCallback}
        run={state.run}
        stepIndex={state.stepIndex}
        steps={state.steps}
        styles={{
          options: {
            arrowColor: "#000",
            backgroundColor: "#000",
            primaryColor: "#000",
            textColor: "#fff",
          },
        }}
      />
    </>
  );
}
