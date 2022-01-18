import React from "react";
import PropTypes from "prop-types";
import { SiMinutemailer } from "react-icons/si";
import { BsPeopleFill } from "react-icons/bs";

import { RouterTabs } from "@certego/certego-ui";
import { Container } from "reactstrap";

export default function Organization({ match, }) {
  console.debug("Organization rendered!");

  const routes = React.useMemo(
    () => [
      {
        key: "organization-myorg",
        location: { pathname: `${match.url}/myorg`, },
        Title: () => (
          <span>
            <BsPeopleFill className="mr-2" />
            Organization
          </span>
        ),
        Component: React.lazy(() => import("./MyOrgPage")),
      },
      {
        key: "organization-invitations",
        location: { pathname: `${match.url}/invitations`, },
        Title: () => (
          <span>
            <SiMinutemailer className="mr-2" />
            Invitations
          </span>
        ),
        Component: React.lazy(() => import("./InvitationsList")),
      },
    ],
    [match.url]
  );

  return (
    <Container fluid>
      <RouterTabs routes={routes} />
    </Container>
  );
}

Organization.propTypes = {
  match: PropTypes.shape({
    url: PropTypes.string.isRequired,
  }).isRequired,
};
