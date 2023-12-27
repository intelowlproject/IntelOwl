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

export const JobStatusBarChart = React.memo(() => {
  console.debug("JobStatusBarChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_STATUS_URI,
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
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobTypeBarChart = React.memo(() => {
  console.debug("JobTypeBarChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_TYPE_URI,
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
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobObsClassificationBarChart = React.memo(() => {
  console.debug("JobObsClassificationBarChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_OBS_CLASSIFICATION_URI,
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
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const JobFileMimetypeBarChart = React.memo(() => {
  console.debug("JobFileMimetypeBarChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_FILE_MIMETYPE_URI,
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
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

// pie charts

export const JobObsNamePieChart = React.memo(() => {
  console.debug("JobObsNamePieChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_OBS_NAME_URI,
      modifierFn: (respData) =>
        Object.entries(respData?.aggregation).map(
          ([observableName, analyzedTimes], index) => ({
            name: observableName.toLowerCase(),
            value: analyzedTimes,
            fill: colors[index],
          }),
        ),
    }),
    [],
  );

  return <PieChartWidget {...chartProps} />;
});

export const JobFileHashPieChart = React.memo(() => {
  console.debug("JobFileHashPieChart rendered!");

  const chartProps = React.useMemo(
    () => ({
      url: JOB_AGG_FILE_MD5_URI,
      modifierFn: (respData) =>
        Object.entries(respData?.aggregation).map(
          ([fileMd5, analyzedTimes], index) => ({
            name: fileMd5.toLowerCase(),
            value: analyzedTimes,
            fill: colors[index],
          }),
        ),
    }),
    [],
  );

  return <PieChartWidget {...chartProps} />;
});
