import create from "zustand";
import axios from "axios";

import { BASE_URI_ORG, ORG_PLUGIN_DISABLE_URI } from "../constants/api";

const useOrganizationStore = create((set, _get) => ({
  loading: false,
  error: null,
  isUserOwner: false,
  noOrg: false,
  organization: {},
  membersCount: undefined,
  members: [],
  pendingInvitations: [],
  pluginsState: {},
  fetchAll: async () => {
    if (_get().loading) return;
    try {
      // set loading
      set({ loading: true });
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
        noOrg: false,
      });
      if (name) {
        const pluginsStateResp = await axios.get(ORG_PLUGIN_DISABLE_URI);
        set({
          pluginsState: pluginsStateResp.data,
        });
      }
    } catch (e) {
      // 404 means user is not part of organization
      if (e.response.status === 404)
        set({
          isUserOwner: false,
          organization: {},
          membersCount: undefined,
          members: [],
          pendingInvitations: [],
          noOrg: true,
        });

      // update error
      set({ loading: false, error: e });
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
      set({ error: e });
    }
  },
  refetchMembers: async () => {
    try {
      // API call
      const resp = await axios.get(
        `${BASE_URI_ORG}?expand=members&fields=members`
      );
      const { members } = resp.data;
      // update members key
      set({ members });
    } catch (e) {
      // update error
      set({ error: e });
    }
  },
  refetchInvs: async () => {
    try {
      // API call
      const resp = await axios.get(
        `${BASE_URI_ORG}?expand=pending_invitations&fields=pending_invitations`
      );
      const { pending_invitations: pendingInvitations } = resp.data;
      // update pendingInvitations key
      set({ pendingInvitations });
    } catch (e) {
      // update error
      set({ error: e });
    }
  },
}));

export default useOrganizationStore;
