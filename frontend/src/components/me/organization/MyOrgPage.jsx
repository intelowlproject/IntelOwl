import React from "react";
import { Alert, Row, Col } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import { LoadingBoundary, ErrorAlert } from "@certego/certego-ui";

import { useOrganizationStore } from "../../../stores";
import {
  OrgInfoCard,
  MembersList,
  PendingInvitationsList,
  OrgCreateButton,
} from "./utils";

export default function MyOrgPage() {
  console.debug("MyOrgPage rendered!");

  // consume store
  const {
    loading,
    error: respErr,
    organization,
    fetchAll,
    noOrg,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        loading: state.loading,
        error: state.error,
        organization: state.organization,
        fetchAll: state.fetchAll,
        noOrg: state.noOrg,
      }),
      []
    )
  );

  // on component mount
  React.useEffect(() => {
    if (Object.keys(organization).length === 0 && !noOrg) {
      fetchAll();
    }
  }, [organization, fetchAll, noOrg]);

  // page title
  useTitle(
    `IntelOwl | Organization ${
      organization?.name ? `(${organization?.name})` : ""
    } `,
    { restoreOnUnmount: true }
  );

  return (
    <LoadingBoundary
      loading={loading}
      error={respErr}
      render={() => (
        <Row className="mt-5 d-flex justify-content-between">
          {/* Organization Info */}
          <Col sm={12} md={8} xl={4} className="mx-sm-auto mx-xl-0">
            <OrgInfoCard />
          </Col>
          {/* Members List */}
          <Col sm={12} md={12} xl={6}>
            <MembersList />
          </Col>
          {/* Pending Invitations List */}
          <Col sm={12} md={12} xl={6}>
            <PendingInvitationsList />
          </Col>
        </Row>
      )}
      renderError={({ error }) => (
        <Row>
          {error?.response?.status === 404 ? (
            <Alert color="secondary" className="mt-3 mx-auto">
              <section>
                <h5 className="text-warning text-center">
                  You are not a member of any organization.
                </h5>
                <p className="text-center">
                  You can choose to create a new organization or join an
                  existing one by asking an organization owner to send you an
                  invitation.
                </p>
              </section>
              <section className="text-center">
                <OrgCreateButton onCreate={fetchAll} />
              </section>
            </Alert>
          ) : (
            <ErrorAlert error={error} />
          )}
        </Row>
      )}
    />
  );
}
