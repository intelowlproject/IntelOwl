import axios from "axios";

import { isObject, objToString } from "@certego/certego-ui";
import useAuthStore from "../stores/useAuthStore";

const shouldInjectToken = (url) => {
  if (url === "/api/auth/login" || url === "/api/auth/register") {
    return false;
  }
  if (url.startsWith("/api/")) {
    return true;
  }
  return false;
};

export default function initAxios() {
  // base config
  axios.defaults.headers.common["Content-Type"] = "application/json";
  axios.defaults.withCredentials = false;
  axios.defaults.certegoUIenableProgressBar = true;
  // request interceptor
  axios.interceptors.request.use((req) => {
    // filter requests deciding whether to inject token or not
    const { token } = useAuthStore.getState();
    if (token && shouldInjectToken(req.url)) {
      req.headers.Authorization = `Token ${token}`;
    }
    return req;
  });
  // response interceptor
  axios.interceptors.response.use(
    (r) => r,
    (error) => {
      if (!error?.response) {
        return Promise.reject(error);
      }
      const err = error;
      const { response } = err;
      // add custom parsed message
      const errField =
        response.data?.errors?.non_field_errors ||
        response.data?.errors ||
        response.data?.detail ||
        response.data?.error ||
        response.data?.message ||
        response.data;
      try {
        err.parsedMsg = isObject(errField) ? objToString(errField) : errField;
      } catch (e) {
        err.parsedMsg = errField;
      }
      // force logout
      if (response?.status === 401 && !response.config.url.includes("logout")) {
        const { service } = useAuthStore.getState();
        service.forceLogout();
      }
      return Promise.reject(err);
    }
  );
}
