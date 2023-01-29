import React from "react";
import { Link } from "react-router-dom";
import { Alert, Row, Container } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { LoadingBoundary, ErrorAlert } from "@certego/certego-ui";
import { useOrganizationStore } from "../../../stores";

import ConfigContainer from "../config/ConfigContainer";
import { OrgCreateButton } from "./utils";

export default function OrgConfig() {
  console.debug("OrgConfigPage rendered!");

  // consume store
  const {
    loading,
    error: respErr,
    organization,
    fetchAll,
    isUserOwner,
    noOrg,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        loading: state.loading,
        error: state.error,
        organization: state.organization,
        fetchAll: state.fetchAll,
        isUserOwner: state.isUserOwner,
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
  }, [noOrg, organization, fetchAll]);

  // page title
  useTitle(
    `IntelOwl | Organization ${
      organization?.name ? `(${organization?.name})` : ""
    } config`,
    { restoreOnUnmount: true }
  );

  return (
    <LoadingBoundary
      loading={loading}
      error={respErr}
      render={() => {
        if (noOrg)
          return (
            <Container>
              <Alert color="secondary" className="mt-3 mx-auto">
                <section>
                  <h5 className="text-warning text-center">
                    You are not owner of any organization.
                  </h5>
                  <p className="text-center">
                    You can choose to create a new organization.
                  </p>
                </section>
                <section className="text-center">
                  <OrgCreateButton onCreate={fetchAll} />
                </section>
              </Alert>
            </Container>
          );
        return (
          <Container>
            <h4>{organization.name}&apos;s plugin configuration</h4>
            <span className="text-muted">
              Note: Your <Link to="/me/config">plugin configuration</Link>{" "}
              overrides your organization&apos;s configuration.
            </span>
            <ConfigContainer
              filterFunction={(item) => item.organization}
              additionalConfigData={{
                organization: organization.name,
              }}
              editable={isUserOwner}
            />
          </Container>
        );
      }}
      renderError={({ error }) => (
        <Row>
          {error?.response?.status === 404 ? (
            <Container>
              <Alert color="secondary" className="mt-3 mx-auto">
                <section>
                  <h5 className="text-warning text-center">
                    You are not owner of any organization.
                  </h5>
                  <p className="text-center">
                    You can choose to create a new organization.
                  </p>
                </section>
                <section className="text-center">
                  <OrgCreateButton onCreate={fetchAll} />
                </section>
              </Alert>
            </Container>
          ) : (
            <ErrorAlert error={error} />
          )}
        </Row>
      )}
    />
  );
}
