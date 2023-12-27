import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { NOTIFICATION_BASE_URI } from "../../../constants/apiURLs";

export async function notificationMarkAsRead(notifId) {
  try {
    await axios.post(`${NOTIFICATION_BASE_URI}/${notifId}/mark-as-read`);
    return Promise.resolve(true);
  } catch (error) {
    addToast("Failed!", error.parsedMsg, "danger", true);
    return Promise.reject(error);
  }
}
