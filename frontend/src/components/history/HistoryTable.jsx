import React from "react";
import PropTypes from "prop-types";
import { Spinner } from "reactstrap";

import { useSearchParams } from "react-router-dom";
import { format, toDate } from "date-fns";

import { datetimeFormatStr, HistoryPages } from "../../constants/miscConst";
import { JobsTable } from "../jobs/table/JobsTable";
import { InvestigationTable } from "../investigations/table/InvestigationsTable";
import { UserEventsTable } from "../userEvents/UserEventsTable";
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

// component
export default function HistoryTable({
  pageType,
  startTimeString,
  endTimeString,
}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const startTimeParam = searchParams.get(startTimeString);
  const endTimeParam = searchParams.get(endTimeString);
  // needed only for investigations table
  const analyzedObjectNameParam =
    searchParams.get("analyzed_object_name") || "";

  // default: 30days
  const defaultFromDate = new Date();
  defaultFromDate.setDate(defaultFromDate.getDate() - 30);
  const [searchFromDateValue, setSearchFromDateValue] =
    React.useState(defaultFromDate);
  const [searchToDateValue, setSearchToDateValue] = React.useState(new Date());

  // state
  const [areParamsInitialized, setAreParamsInitialized] = React.useState(false); // used to prevent a request with wrong params
  // needed only for investigations table
  const [searchNameRequest, setSearchNameRequest] = React.useState("");

  React.useEffect(() => {
    if (startTimeParam) {
      setSearchFromDateValue(toDate(startTimeParam));
    }
    if (endTimeParam) {
      setSearchToDateValue(toDate(endTimeParam));
    }
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
      (startTimeParam !== format(searchFromDateValue, datetimeFormatStr) ||
        endTimeParam !== format(searchToDateValue, datetimeFormatStr) ||
        analyzedObjectNameParam !== searchNameRequest)
    ) {
      const currentParams = {};
      // @ts-ignore
      searchParams.entries().forEach((element) => {
        const [paramName, paramValue] = element;
        currentParams[paramName] = paramValue;
      });

      const newParams = { ...currentParams };
      newParams[startTimeParam] = format(
        searchFromDateValue,
        datetimeFormatStr,
      );
      newParams[endTimeParam] = format(searchToDateValue, datetimeFormatStr);
      if (pageType === HistoryPages.INVESTIGAITONS) {
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

  return areParamsInitialized ? ( // this "if" avoid one request
    <>
      {pageType === HistoryPages.JOBS && (
        <JobsTable
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      )}
      {pageType === HistoryPages.INVESTIGAITONS && (
        <InvestigationTable
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
          searchNameRequest={searchNameRequest}
        />
      )}
      {pageType === HistoryPages.USER_EVENTS && (
        <UserEventsTable
          title="Artifacts evaluations"
          url={USER_EVENT_ANALYZABLE}
          columns={userAnalyzableEventsTableColumns}
          description="Evaluations related to artifacts given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      )}
      {pageType === HistoryPages.USER_DOMAIN_WILDCARD_EVENTS && (
        <UserEventsTable
          title="Domain wildcard evaluations"
          url={USER_EVENT_DOMAIN_WILDCARD}
          columns={userDomainWildcardEventsTableColumns}
          description="Evaluations of domain wildcards given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      )}
      {pageType === HistoryPages.USER_IP_WILDCARD_EVENTS && (
        <UserEventsTable
          title="Ip wildcard evaluations"
          url={USER_EVENT_IP_WILDCARD}
          columns={userIpWildcardEventsTableColumns}
          description="Evaluations related to networks given by users"
          searchFromDateValue={searchFromDateValue}
          searchToDateValue={searchToDateValue}
        />
      )}
    </>
  ) : (
    <Spinner />
  );
}

HistoryTable.propTypes = {
  pageType: PropTypes.string.isRequired,
  startTimeString: PropTypes.string.isRequired,
  endTimeString: PropTypes.string.isRequired,
};
