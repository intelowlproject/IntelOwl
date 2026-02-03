import React from "react";
import PropTypes from "prop-types";
import { Spinner } from "reactstrap";

import { useSearchParams } from "react-router-dom";

import { HistoryPages } from "../../constants/miscConst";
import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_DOMAIN_WILDCARD,
  USER_EVENT_IP_WILDCARD,
} from "../../constants/apiURLs";
import {
  userAnalyzableEventsTableColumns,
  userDomainWildcardEventsTableColumns,
  userIpWildcardEventsTableColumns,
} from "../userEvents/userEventsTableColumns";

const JobsTable = React.lazy(() => import("../jobs/table/JobsTable"));
const InvestigationTable = React.lazy(
  () => import("../investigations/table/InvestigationsTable"),
);
const UserEventsTable = React.lazy(
  () => import("../userEvents/UserEventsTable"),
);

// component
export function HistoryTable({ pageType, startTimeParam, endTimeParam }) {
  console.debug("HistoryTable rendered");
  const [searchParams, setSearchParams] = useSearchParams();
  // needed only for investigations table
  const analyzedObjectNameParam =
    searchParams.get("analyzed_object_name") || "";

  const [searchFromDateValue] = React.useState(startTimeParam);
  const [searchToDateValue] = React.useState(endTimeParam);

  // state
  const [areParamsInitialized, setAreParamsInitialized] = React.useState(false); // used to prevent a request with wrong params
  // needed only for investigations table
  const [searchNameRequest, setSearchNameRequest] = React.useState("");

  React.useEffect(() => {
    if (analyzedObjectNameParam) {
      setSearchNameRequest(analyzedObjectNameParam);
    }
    setAreParamsInitialized(true);
  }, [analyzedObjectNameParam, startTimeParam, endTimeParam]);

  React.useEffect(() => {
    // After the initialization each time the time picker change, update the url
    // Note: this check is required to avoid infinite loop (url update time picker and time picker update url)
    if (
      areParamsInitialized &&
      (startTimeParam !== searchFromDateValue ||
        endTimeParam !== searchToDateValue ||
        analyzedObjectNameParam !== searchNameRequest)
    ) {
      const currentParams = {};
      // @ts-ignore
      searchParams.entries().forEach((element) => {
        const [paramName, paramValue] = element;
        currentParams[paramName] = paramValue;
      });

      const newParams = { ...currentParams };
      newParams[startTimeParam] = searchFromDateValue;
      newParams[endTimeParam] = searchToDateValue;
      if (pageType === HistoryPages.INVESTIGAITON) {
        newParams.analyzed_object_name = searchNameRequest;
      }
      setSearchParams(newParams);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    setSearchParams,
    areParamsInitialized,
    searchFromDateValue,
    searchToDateValue,
  ]);

  let tableComponent;
  switch (pageType) {
    case HistoryPages.INVESTIGAITON:
      tableComponent = (
        <InvestigationTable
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
          searchNameRequest={searchNameRequest}
        />
      );
      break;
    case HistoryPages.USER_EVENT:
      tableComponent = (
        <UserEventsTable
          title="Artifacts evaluations"
          url={USER_EVENT_ANALYZABLE}
          columns={userAnalyzableEventsTableColumns}
          description="Evaluations related to artifacts given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      );
      break;
    case HistoryPages.USER_DOMAIN_WILDCARD_EVENT:
      tableComponent = (
        <UserEventsTable
          title="Domain wildcard evaluations"
          url={USER_EVENT_DOMAIN_WILDCARD}
          columns={userDomainWildcardEventsTableColumns}
          description="Evaluations of domain wildcards given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      );
      break;
    case HistoryPages.USER_IP_WILDCARD_EVENT:
      tableComponent = (
        <UserEventsTable
          title="Ip wildcard evaluations"
          url={USER_EVENT_IP_WILDCARD}
          columns={userIpWildcardEventsTableColumns}
          description="Evaluations related to networks given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      );
      break;
    default:
      tableComponent = (
        <JobsTable
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      );
  }

  return areParamsInitialized ? ( // this "if" avoid one request
    tableComponent
  ) : (
    <Spinner />
  );
}

HistoryTable.propTypes = {
  pageType: PropTypes.string.isRequired,
  startTimeParam: PropTypes.string.isRequired,
  endTimeParam: PropTypes.string.isRequired,
};
