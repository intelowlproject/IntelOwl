import axios from "axios";

import { addToast } from "@certego/certego-ui";
import { PLUGIN_REPORT_QUERIES } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";

export async function pluginReportQueries(body) {
  try {
    const resp = await axios.get(PLUGIN_REPORT_QUERIES, { params: body });
    return resp;
  } catch (error) {
    addToast("Query failed!", prettifyErrors(error), "danger", true);
    return Promise.reject(error);
  }
}
