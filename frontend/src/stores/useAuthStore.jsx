import axios from "axios";
import create from "zustand";

import { addToast } from "@certego/certego-ui";

import { USERACCESS_URI, AUTH_BASE_URI } from "../constants/api";
import useRecentScansStore from "./useRecentScansStore";

// constants
const onLogout = useRecentScansStore.getState().clear;
const TOKEN_STORAGE_KEY = "INTELOWL_AUTH_TOKEN";

// hook/ store
const useAuthStore = create((set, get) => ({
  loading: false,
  token: localStorage.getItem(TOKEN_STORAGE_KEY) || null,
  user: { full_name: "", first_name: "", last_name: "", email: "", },
  access: null,
  isAuthenticated: () => !!get().token,
  updateToken: (newValue) => {
    localStorage.setItem(TOKEN_STORAGE_KEY, newValue.toString());
    set({ token: newValue, });
  },
  deleteToken: () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    set({ token: null, });
  },
  service: {
    fetchUserAccess: async () => {
      try {
        const resp = await axios.get(USERACCESS_URI, {
          certegoUIenableProgressBar: false,
        });
        set({
          user: resp.data.user,
          access: resp.data.access,
        });
      } catch (err) {
        addToast(
          "Error fetching user access information!",
          err.parsedMsg,
          "danger"
        );
      }
    },
    loginUser: async (body) => {
      try {
        set({ loading: true, });
        const resp = await axios.post(`${AUTH_BASE_URI}/login`, body, {
          certegoUIenableProgressBar: false,
        });
        get().updateToken(resp.data.token, {
          expires: new Date(resp.data.expiry),
        });
        addToast("You've been logged in!", null, "success");
        return Promise.resolve(resp);
      } catch (err) {
        addToast("Login failed!", err.parsedMsg, "danger", true);
        return Promise.reject(err);
      } finally {
        set({ loading: false, });
      }
    },
    logoutUser: async () => {
      set({ loading: true, });
      const onLogoutCb = () => {
        get().deleteToken();
        set({ loading: false, });
        onLogout();
        addToast("Logged out!", null, "info");
      };
      return axios
        .post(`${AUTH_BASE_URI}/logout`, null, {
          certegoUIenableProgressBar: false,
        })
        .then(onLogoutCb)
        .catch(onLogoutCb);
    },
    forceLogout: () => {
      addToast(
        "Invalid token. You will be logged out shortly",
        null,
        "spinner",
        true,
        1000
      );
      return setTimeout(get().service.logoutUser, 500);
    },
  },
}));

export default useAuthStore;
