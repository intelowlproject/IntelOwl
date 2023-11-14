import axios from "axios";

import { addToast } from "@certego/certego-ui";
import { COMMENT_BASE_URI } from "../../../../../constants/apiURLs";
import { prettifyErrors } from "../../../../../utils/api";

export async function createComment(formValues) {
  try {
    const resp = await axios.post(`${COMMENT_BASE_URI}`, formValues);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
    return Promise.reject(e);
  }
}

export async function deleteComment(commentId) {
  try {
    const resp = await axios.delete(`${COMMENT_BASE_URI}/${commentId}`);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
    return Promise.reject(e);
  }
}
