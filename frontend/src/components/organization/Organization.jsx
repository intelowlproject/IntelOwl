import React, { Suspense } from "react";
import { SiMinutemailer } from "react-icons/si";
import { BsPeopleFill } from "react-icons/bs";

import { RouterTabs, FallBackLoading } from "@certego/certego-ui";
import { Container } from "reactstrap";

const MyOrgPage = React.lazy(() => import("./MyOrgPage"));
const InvitationsList = React.lazy(() => import("./InvitationsList"));

const routes = [
  {
    key: "organization-myorg",
    location: "myorg",
    Title: () => (
      <span>
        <BsPeopleFill className="me-2" />
        Organization
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <MyOrgPage />
      </Suspense>
    ),
  },
  {
    key: "organization-invitations",
    location: "invitations",
    Title: () => (
      <span>
        <SiMinutemailer />
        &nbsp;Invitations
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <InvitationsList />
      </Suspense>
    ),
  },
];

export default function Organization() {
  console.debug("Organization rendered!");

  return (
    <Container fluid>
      <RouterTabs routes={routes} />
    </Container>
  );
}
