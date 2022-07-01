import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { BASE_URI_INVITATION, BASE_URI_ORG } from "../../../constants/api";

// ORGANIZATION

async function createOrganization(body) {
  try {
    const resp = await axios.post(BASE_URI_ORG, body);
    addToast(
      `You are now the owner of ${resp?.data?.name} organization.`,
      null,
      "success",
      true
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function deleteOrganization(orgName) {
  try {
    const resp = await axios.delete(BASE_URI_ORG);
    addToast(
      `Organization ${orgName} was deleted.`,
      null,
      "success",
      true,
      6000
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function removeMemberFromOrg(username) {
  try {
    const resp = await axios.post(`${BASE_URI_ORG}/remove_member`, {
      username,
    });
    addToast(
      `User @${username} was removed as a member.`,
      null,
      "success",
      true
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function leaveOrganization(orgName) {
  try {
    const resp = await axios.post(`${BASE_URI_ORG}/leave`);
    addToast(
      `You are no longer a member of the ${orgName} organization.`,
      null,
      "success",
      true
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

// INVITATION

async function sendInvite(body) {
  try {
    const resp = await axios.post(`${BASE_URI_ORG}/invite`, body);
    addToast("Invite Sent!", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Invite Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function acceptInvitation(invId, orgName) {
  try {
    const resp = await axios.post(`${BASE_URI_INVITATION}/${invId}/accept`);
    addToast(
      "Congratulations!",
      `You are now a member of the ${orgName} organization`,
      "success",
      true,
      6000
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function declineInvitation(invId, orgName) {
  try {
    const resp = await axios.post(`${BASE_URI_INVITATION}/${invId}/decline`);
    addToast(
      `Invitation from ${orgName} organization was declined.`,
      null,
      "info",
      true
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

async function deleteInvitation(invId, username) {
  try {
    const resp = await axios.delete(`${BASE_URI_INVITATION}/${invId}`);
    addToast(
      `Invitation to user @${username} was deleted.`,
      null,
      "success",
      true
    );
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg, "danger", true);
    return Promise.reject(e);
  }
}

export {
  BASE_URI_INVITATION,
  BASE_URI_ORG,
  createOrganization,
  deleteOrganization,
  removeMemberFromOrg,
  leaveOrganization,
  sendInvite,
  acceptInvitation,
  declineInvitation,
  deleteInvitation,
};
