import { useAxiosComponentLoader } from "@certego/certego-ui";
import React from "react";
import { Alert, Container, Row } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import { CUSTOM_CONFIG_URI } from "./api";

export default function Config() {
  console.debug("Config rendered!");

  // page title
  useTitle("IntelOwl | Config", {
    restoreOnUnmount: true,
  });

  const [respData, Loader, refetch] = useAxiosComponentLoader(
    {
      url: CUSTOM_CONFIG_URI,
    },
    (resp) => resp.filter((item) => !item.organization)
  );
  console.debug("respData", refetch);

  return (
    <Container>
      {/* Alert */}
      <Row className="my-4">
        <Alert color="secondary" className="mx-3 mx-md-auto text-center">
          <span>
            You can generate an API key to access IntelOwl&apos;s RESTful
            API.&nbsp; Take a look to the available Python and Go clients.
          </span>
        </Alert>
      </Row>
      {/* API Access */}
      <h6>API Access</h6>
      {/* Sessions List */}
      <h6>Browser Sessions</h6>
      <Loader
        render={() => (
          <ol>
            {respData.map((item) => (
              <li key={item.name}>{item.attribute}</li>
            ))}
          </ol>
        )}
      />
    </Container>
  );
}
