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
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(JobStatusColors).map(([dkey, color]) => (
          <Bar
            stackId="jobstatus"
            key={dkey}
            dataKey={dkey}
            fill={`var(--${color})`}
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
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(JobTypeColors).map(([dataKey, color]) => (
          <Bar stackId="jobtype" key={dataKey} dataKey={dataKey} fill={color} />
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
      accessorFnAggregation: (d) => d,
      componentsFn: () =>
        Object.entries(ObservableClassificationColors).map(([dKey, color]) => (
          <Bar stackId="joboc" key={dKey} dataKey={dKey} fill={color} />
        )),
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
      accessorFnAggregation: (d) => d?.aggregation,
      componentsFn: (respData) => {
        const { values: mtList } = respData;
        if (!mtList || !mtList?.length) return null;
        return mtList.map((mc, i) => (
          <Bar
            stackId="jobfilemimetype"
            key={mc}
            dataKey={mc}
            fill={colors[i]}
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
        Object.entries(respData?.aggregation).map(([key, val], i) => ({
          name: key.toLowerCase(),
          value: val,
          fill: colors[i],
        })),
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
        Object.entries(respData?.aggregation).map(([key, val], i) => ({
          name: key.toLowerCase(),
          value: val,
          fill: colors[i],
        })),
    }),
    [],
  );

  return <PieChartWidget {...chartProps} />;
});
