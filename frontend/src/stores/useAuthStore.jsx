import axios from "axios";
import { create } from "zustand";
import { addToast } from "@certego/certego-ui";
import Cookies from "js-cookie";
import { USERACCESS_URI, AUTH_BASE_URI } from "../constants/apiURLs";

// Constants
const CSRF_TOKEN = "csrftoken";

// Auth Store
export const useAuthStore = create((set, get) => {
  const updateToken = () => set({ CSRFToken: Cookies.get(CSRF_TOKEN) || "" });
  const deleteToken = () => {
    Cookies.remove(CSRF_TOKEN);
    set({ CSRFToken: "" });
  };

  const handleRequest = async (request, successMsg, errorMsg) => {
    try {
      set({ loading: true });
      const response = await request();
      if (successMsg) addToast(successMsg, null, "success");
      return response;
    } catch (err) {
      if (errorMsg) addToast(errorMsg, err.parsedMsg, "danger", true);
      return Promise.reject(err);
    } finally {
      set({ loading: false });
    }
  };

  return {
    loading: false,
    CSRFToken: Cookies.get(CSRF_TOKEN) || "",
    user: {
      username: "",
      full_name: "",
      first_name: "",
      last_name: "",
      email: "",
      is_staff: false,
    },
    access: null,
    isAuthenticated: () => !!get().CSRFToken,
    updateToken,
    deleteToken,
    service: {
      fetchUserAccess: async () => {
        try {
          const { data } = await axios.get(USERACCESS_URI, {
            certegoUIenableProgressBar: false,
          });
          set({ user: data.user, access: data.access });
        } catch (err) {
          addToast("Error fetching user access information!", err.parsedMsg, "danger");
        }
      },
      loginUser: (body) =>
        handleRequest(
          () => axios.post(`${AUTH_BASE_URI}/login`, body, { certegoUIenableProgressBar: false }),
          "You've been logged in!",
          "Login failed!"
        ).then(() => get().updateToken()),
      logoutUser: async () => {
        set({ loading: true });
        const onLogoutCb = () => {
          deleteToken();
          addToast("Logged out!", null, "info");
          set({ loading: false });
        };
        return axios.post(`${AUTH_BASE_URI}/logout`, null, { certegoUIenableProgressBar: false }).then(onLogoutCb).catch(onLogoutCb);
      },
      forceLogout: () => {
        addToast("Invalid token. You will be logged out shortly", null, "spinner", true, 1000);
        setTimeout(get().service.logoutUser, 500);
      },
      changePassword: (values) =>
        handleRequest(
          () => axios.post(`${AUTH_BASE_URI}/changepassword`, values, { certegoUIenableProgressBar: false }),
          null,
          "Password change failed!"
        ),
    },
  };
});
