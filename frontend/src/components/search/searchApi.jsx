import axios from "axios";

import { addToast } from "@certego/certego-ui";
import { PLUGIN_REPORT_QUERIES } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";

/** @param {object} body @param {number} pageSize @param {number} page */
export async function pluginReportQueries(body, pageSize, page = 1) {
  const params = { ...body, page, page_size: pageSize };
  try {
    const resp = await axios.get(PLUGIN_REPORT_QUERIES, { params });
    return {
      results: resp.data.results,
      count: resp.data.count,
      totalPages: resp.data.total_pages,
    };
  } catch (error) {
    addToast("Query failed!", prettifyErrors(error), "danger", true);
    return Promise.reject(error);
  }
}
