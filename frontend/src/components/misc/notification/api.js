import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { NOTIFICATION_BASE_URI } from "../../../constants/api";

export async function notificationMarkAsRead(notifId) {
  try {
    await axios.post(`${NOTIFICATION_BASE_URI}/${notifId}/mark-as-read`);
    return Promise.resolve(true);
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}
