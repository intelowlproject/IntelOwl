import React from "react";
import { Bar } from "recharts";
import PropTypes from "prop-types";

import { getRandomColorsArray, AnyChartWidget } from "@certego/certego-ui";

import {
  JobTypeColors,
  ObservableClassificationColors,
  TLPColors,
} from "../../constants/colorConst";

import { JobStatuses } from "../../constants/jobConst";

import {
  JOB_AGG_STATUS_URI,
  JOB_AGG_TYPE_URI,
  JOB_AGG_OBS_CLASSIFICATION_URI,
  JOB_AGG_FILE_MIMETYPE_URI,
  JOB_AGG_TOP_PLAYBOOK_URI,
  JOB_AGG_TOP_USER_URI,
  JOB_AGG_TOP_TLP_URI,
} from "../../constants/apiURLs";

// constants
const colors = getRandomColorsArray(10, true);

// bar charts
export const JobStatusBarChart = React.memo((props) => {
  console.debug("JobStatusBarChart rendered!");
  const ORG_JOB_AGG_STATUS_URI = `${JOB_AGG_STATUS_URI}?org=${props.orgName}`;

  const mappingStatusColor = Object.freeze({
    [JobStatuses.PENDING]: "#ffffff",
    [JobStatuses.REPORTED_WITH_FAILS]: "#ffa31a",
    [JobStatuses.REPORTED_WITHOUT_FAILS]: "#009933",
    [JobStatuses.FAILED]: "#cc0000",
  });

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_STATUS_URI,
      accessorFnAggregation: (jobStatusesPerDay) => jobStatusesPerDay,
      componentsFn: () =>
        Object.entries(mappingStatusColor).map(([jobStatus, jobColor]) => (
          <Bar
            stackId="jobstatus"
            key={jobStatus}
            dataKey={jobStatus}
            fill={jobColor}
          />
        )),
    }),
    [ORG_JOB_AGG_STATUS_URI, mappingStatusColor],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTypeBarChart = React.memo((props) => {
  console.debug("JobTypeBarChart rendered!");
  const ORG_JOB_AGG_TYPE_URI = `${JOB_AGG_TYPE_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_TYPE_URI,
      accessorFnAggregation: (jobTypesPerDay) => jobTypesPerDay,
      componentsFn: () =>
        Object.entries(JobTypeColors).map(([jobType, jobColor]) => (
          <Bar
            stackId="jobtype"
            key={jobType}
            dataKey={jobType}
            fill={jobColor}
          />
        )),
    }),
    [ORG_JOB_AGG_TYPE_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobObsClassificationBarChart = React.memo((props) => {
  console.debug("JobObsClassificationBarChart rendered!");
  const ORG_JOB_AGG_OBS_CLASSIFICATION_URI = `${JOB_AGG_OBS_CLASSIFICATION_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_OBS_CLASSIFICATION_URI,
      accessorFnAggregation: (jobObservableSubTypesPerDay) =>
        jobObservableSubTypesPerDay,
      componentsFn: () =>
        Object.entries(ObservableClassificationColors).map(
          ([observableClassification, observableColor]) => (
            <Bar
              stackId="joboc"
              key={observableClassification}
              dataKey={observableClassification}
              fill={observableColor}
            />
          ),
        ),
    }),
    [ORG_JOB_AGG_OBS_CLASSIFICATION_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobFileMimetypeBarChart = React.memo((props) => {
  console.debug("JobFileMimetypeBarChart rendered!");
  const ORG_JOB_AGG_FILE_MIMETYPE_URI = `${JOB_AGG_FILE_MIMETYPE_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_FILE_MIMETYPE_URI,
      accessorFnAggregation: (jobFileSubTypesPerDay) =>
        jobFileSubTypesPerDay?.aggregation,
      componentsFn: (respData) => {
        const { values: mimetypeList } = respData;
        if (!mimetypeList || !mimetypeList?.length) return null;
        return mimetypeList.map((mimetype, index) => (
          <Bar
            stackId="jobfilemimetype"
            key={mimetype}
            dataKey={mimetype}
            fill={colors[index]}
          />
        ));
      },
    }),
    [ORG_JOB_AGG_FILE_MIMETYPE_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTopPlaybookBarChart = React.memo((props) => {
  console.debug("JobTopPlaybookBarChart rendered!");
  const ORG_JOB_AGG_TOP_PLAYBOOK_URI = `${JOB_AGG_TOP_PLAYBOOK_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_TOP_PLAYBOOK_URI,
      accessorFnAggregation: (jobPlaybooks) => jobPlaybooks?.aggregation,
      componentsFn: (playbookUsageAggregatedByPlaybookName) => {
        const { values } = playbookUsageAggregatedByPlaybookName;
        if (!values || !values?.length) return null;
        return values.map((playbookName, index) => (
          <Bar
            stackId="jobtopplaybook"
            key={playbookName}
            dataKey={playbookName}
            fill={colors[index]}
          />
        ));
      },
    }),
    [ORG_JOB_AGG_TOP_PLAYBOOK_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTopUserBarChart = React.memo((props) => {
  console.debug("JobTopUserBarChart rendered!");
  const ORG_JOB_AGG_TOP_USER_URI = `${JOB_AGG_TOP_USER_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_TOP_USER_URI,
      accessorFnAggregation: (jobUsers) => jobUsers?.aggregation,
      componentsFn: (JobUsageAggregatedByUsername) => {
        const { values } = JobUsageAggregatedByUsername;
        if (!values || !values?.length) return null;
        return values.map((username, index) => (
          <Bar
            stackId="jobtopuser"
            key={username}
            dataKey={username}
            fill={colors[index]}
          />
        ));
      },
    }),
    [ORG_JOB_AGG_TOP_USER_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTopTLPBarChart = React.memo((props) => {
  console.debug("JobTopTLPBarChart rendered!");
  const ORG_JOB_AGG_TOP_TLP_URI = `${JOB_AGG_TOP_TLP_URI}?org=${props.orgName}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_TOP_TLP_URI,
      accessorFnAggregation: (jobTLPs) => jobTLPs?.aggregation,
      componentsFn: (JobUsageAggregatedByTLP) => {
        const { values } = JobUsageAggregatedByTLP;
        if (!values || !values?.length) return null;
        return values.map((tlp) => (
          <Bar
            stackId="jobtopuser"
            key={tlp}
            dataKey={tlp}
            fill={TLPColors[tlp]}
          />
        ));
      },
    }),
    [ORG_JOB_AGG_TOP_TLP_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

JobStatusBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobTypeBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobObsClassificationBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobFileMimetypeBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobTopPlaybookBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobTopUserBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};

JobTopTLPBarChart.propTypes = {
  orgName: PropTypes.string.isRequired,
};
