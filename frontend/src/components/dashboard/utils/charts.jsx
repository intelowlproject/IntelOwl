import React from "react";
import { Bar } from "recharts";

import {
  getRandomColorsArray,
  AnyChartWidget,
  PieChartWidget,
} from "@certego/certego-ui";

import {
  JobStatusColors,
  JobTypeColors,
  ObservableClassificationColors,
} from "../../../constants/colorConst";

import {
  JOB_AGG_STATUS_URI,
  JOB_AGG_TYPE_URI,
  JOB_AGG_OBS_CLASSIFICATION_URI,
  JOB_AGG_FILE_MIMETYPE_URI,
  JOB_AGG_OBS_NAME_URI,
  JOB_AGG_FILE_MD5_URI,
} from "../../../constants/apiURLs";

// constants
const colors = getRandomColorsArray(10, true);

// bar charts

export const JobStatusBarChart = React.memo((props) => {
  console.debug("JobStatusBarChart rendered!");
  /* eslint-disable */
  var ORG_JOB_AGG_STATUS_URI = JOB_AGG_STATUS_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_STATUS_URI = `${JOB_AGG_STATUS_URI}?org=${getValue}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_STATUS_URI,
      accessorFnAggregation: (jobStatusesPerDay) => jobStatusesPerDay,
      componentsFn: () =>
        Object.entries(JobStatusColors).map(([jobStatus, jobColor]) => (
          <Bar
            stackId="jobstatus"
            key={jobStatus}
            dataKey={jobStatus}
            fill={`var(--${jobColor})`}
          />
        )),
    }),
    [ORG_JOB_AGG_STATUS_URI],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTypeBarChart = React.memo((props) => {
  console.debug("JobTypeBarChart rendered!");
  /* eslint-disable */
  var ORG_JOB_AGG_TYPE_URI = JOB_AGG_TYPE_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_TYPE_URI = `${JOB_AGG_TYPE_URI}?org=${getValue}`;

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
  /* eslint-disable */
  var ORG_JOB_AGG_OBS_CLASSIFICATION_URI = JOB_AGG_OBS_CLASSIFICATION_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_OBS_CLASSIFICATION_URI = `${JOB_AGG_OBS_CLASSIFICATION_URI}?org=${getValue}`;

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
  /* eslint-disable */
  var ORG_JOB_AGG_FILE_MIMETYPE_URI = JOB_AGG_FILE_MIMETYPE_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_FILE_MIMETYPE_URI = `${JOB_AGG_FILE_MIMETYPE_URI}?org=${getValue}`;

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

// pie charts

export const JobObsNamePieChart = React.memo((props) => {
  console.debug("JobObsNamePieChart rendered!");
  /* eslint-disable */
  var ORG_JOB_AGG_OBS_NAME_URI = JOB_AGG_OBS_NAME_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_OBS_NAME_URI = `${JOB_AGG_OBS_NAME_URI}?org=${getValue}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_OBS_NAME_URI,
      modifierFn: (respData) =>
        Object.entries(respData?.aggregation).map(
          ([observableName, analyzedTimes], index) => ({
            name: observableName.toLowerCase(),
            value: analyzedTimes,
            fill: colors[index],
          }),
        ),
    }),
    [ORG_JOB_AGG_OBS_NAME_URI],
  );

  return <PieChartWidget {...chartProps} />;
});

export const JobFileHashPieChart = React.memo((props) => {
  console.debug("JobFileHashPieChart rendered!");
  /* eslint-disable */
  var ORG_JOB_AGG_FILE_MD5_URI = JOB_AGG_FILE_MD5_URI;
  const parameter = props.sendOrgState;
  const getValue = parameter.key;
  ORG_JOB_AGG_FILE_MD5_URI = `${JOB_AGG_FILE_MD5_URI}?org=${getValue}`;

  const chartProps = React.useMemo(
    () => ({
      url: ORG_JOB_AGG_FILE_MD5_URI,
      modifierFn: (respData) =>
        Object.entries(respData?.aggregation).map(
          ([fileMd5, analyzedTimes], index) => ({
            name: fileMd5.toLowerCase(),
            value: analyzedTimes,
            fill: colors[index],
          }),
        ),
    }),
    [ORG_JOB_AGG_FILE_MD5_URI],
  );

  return <PieChartWidget {...chartProps} />;
});
