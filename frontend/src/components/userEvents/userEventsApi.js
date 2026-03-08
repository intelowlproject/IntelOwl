import axios from "axios";
import { addToast } from "@certego/certego-ui";

import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_DOMAIN_WILDCARD,
  USER_EVENT_IP_WILDCARD,
} from "../../constants/apiURLs";
import { AnalyzableHistoryTypes } from "../../../constants/miscConst";

export const deleteUserEvent = async (id, type) => {
  let url = "";
  if (type === AnalyzableHistoryTypes.USER_EVENT) {
    url = `${USER_EVENT_ANALYZABLE}/${id}`;
  } else if (type === AnalyzableHistoryTypes.USER_DOMAIN_WILDCARD_EVENT) {
    url = `${USER_EVENT_DOMAIN_WILDCARD}/${id}`;
  } else if (type === AnalyzableHistoryTypes.USER_IP_WILDCARD_EVENT) {
    url = `${USER_EVENT_IP_WILDCARD}/${id}`;
  } else {
    throw new Error(`Unknown user event type: ${type}`);
  }

  try {
    const response = await axios.delete(url);
    addToast(
      "Success",
      "User event deleted successfully",
      "success",
      false,
      3000,
    );
    return response.data;
  } catch (err) {
    addToast(
      "Error deleting user event",
      err?.response?.data?.detail || "An error occurred",
      "danger",
      false,
      5000,
    );
    throw err;
  }
};
