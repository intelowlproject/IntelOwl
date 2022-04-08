import create from "zustand";
import axios from "axios";

import { BASE_URI_ORG } from "../constants/api";

const useOrganizationStore = create((set, get) => ({
  loading: true,
  error: null,
  isUserOwner: false,
  organization: {},
  membersCount: undefined,
  members: [],
  pendingInvitations: [],
  fetchAll: async () => {
    try {
      // set loading
      set({ loading: true, });
      // API call
      const resp = await axios.get(
        `${BASE_URI_ORG}?expand=members,pending_invitations`
      );
      // destructure response data
      const {
        name,
        owner,
        created_at: establishedAt,
        members_count: membersCount,
        is_user_owner: isUserOwner,
        members,
        pending_invitations: pendingInvitations,
      } = resp.data;
      // update state
      set({
        loading: false,
        error: null,
        isUserOwner,
        organization: {
          name,
          establishedAt,
          owner,
        },
        membersCount,
        members,
        pendingInvitations,
      });
    } catch (e) {
      // update error
      set({ loading: false, error: e, });
    }
  },
  fetchOnlyBasicInfo: async () => {
    try {
      // API call
      const resp = await axios.get(BASE_URI_ORG);
      // destructure response data
      const {
        name,
        owner,
        created_at: establishedAt,
        members_count: membersCount,
        is_user_owner: isUserOwner,
      } = resp.data;
      // update state
      set({
        isUserOwner,
        organization: {
          name,
          establishedAt,
          owner,
        },
        membersCount,
      });
    } catch (e) {
      // update error
      set({ error: e, });
    }
  },
  refetchMembers: async () => {
    try {
      // API call
      const resp = await axios.get(
        `${BASE_URI_ORG}?expand=members&fields=members`
      );
      const { members, } = resp.data;
      // update members key
      set({ members, });
    } catch (e) {
      // update error
      set({ error: e, });
    }
  },
  refetchInvs: async () => {
    try {
      // API call
      const resp = await axios.get(
        `${BASE_URI_ORG}?expand=pending_invitations&fields=pending_invitations`
      );
      const { pending_invitations: pendingInvitations, } = resp.data;
      // update pendingInvitations key
      set({ pendingInvitations, });
    } catch (e) {
      // update error
      set({ error: e, });
    }
  },
}));

export default useOrganizationStore;
