import React from "react";
import { Alert, Row, Col, ButtonGroup } from "reactstrap";
import { MdVisibility, MdVisibilityOff } from "react-icons/md";
import { VscDebugDisconnect } from "react-icons/vsc";
import { IoMdAdd } from "react-icons/io";

import {
  ContentSection,
  ErrorAlert,
  IconButton,
  DateHoverable,
  CopyToClipboardButton,
  useAxiosComponentLoader,
  confirm,
} from "@certego/certego-ui";

import { APIACCESS_BASE_URI, createNewToken, deleteToken } from "./api";

function GenerateIcon() {
  return (
    <span>
      Generate&nbsp;
      <IoMdAdd />
    </span>
  );
}

export default function APIAccess() {
  console.debug("APIAccess rendered!");

  // API
  const [respData, Loader, refetch] = useAxiosComponentLoader({
    url: APIACCESS_BASE_URI,
  });

  // local state
  const [tokenVisible, setTokenVisible] = React.useState(false);

  // callbacks
  const createTokenCb = React.useCallback(async () => {
    await createNewToken();
    // reload after 500ms
    setTimeout(refetch, 500);
  }, [refetch]);
  const deleteTokenCb = React.useCallback(async () => {
    const answer = await confirm({
      message: (
        <div>
          <p className="text-warning fst-italic">
            Note: This is an irreversible operation.
          </p>
          <p>
            Once deleted, you cannot use this API key to access IntelOwl&apos;s
            API. However, you will be able to generate a new one.
          </p>
          Are you sure you wish to proceed ?
        </div>
      ),
      confirmText: "Yes",
    });
    if (answer) {
      try {
        await deleteToken();
        // reload after 500ms
        setTimeout(refetch, 500);
      } catch (e) {
        // handled inside deleteToken
      }
    }
  }, [refetch]);

  return (
    <Loader
      // Normal render
      render={() => (
        <>
          {/* API key details */}
          <Row className="d-flex g-0">
            <Col sm={6} lg={3}>
              <small className="text-muted me-1">Created</small>
              <DateHoverable
                id="apikey__created"
                value={respData?.created}
                format="hh:mm a MMM do, yyyy"
                title="Session create date"
                showAgo
              />
            </Col>
            <Col sm={6} lg={3}>
              <small className="text-muted me-1">Expires</small>
              <DateHoverable
                id="apikey__expires"
                value={respData?.expiry}
                format="hh:mm a MMM do, yyyy"
                title="Session expiry date"
                showAgo
              />
            </Col>
          </Row>
          {/* API key toggler */}
          <Row className="mt-4 d-flex g-0">
            <Col md={8} lg={5} className="mx-auto">
              <ContentSection className="bg-darker d-flex-center flex-nowrap">
                {tokenVisible ? (
                  <CopyToClipboardButton
                    id="apiaccess__token"
                    text={respData?.token}
                    showOnHover
                  >
                    {respData?.token}
                  </CopyToClipboardButton>
                ) : (
                  <div className="blurry-text text-truncate">
                    tokentokentokentokentokentoken
                  </div>
                )}
                <ButtonGroup className="ms-auto" size="sm">
                  <IconButton
                    id="toggle-show-apikey-btn"
                    color="dark"
                    title={tokenVisible ? "Hide API key" : "Show API Key"}
                    className="ms-2 border border-dark"
                    Icon={tokenVisible ? MdVisibility : MdVisibilityOff}
                    onClick={() => setTokenVisible((s) => !s)}
                  />
                  <IconButton
                    id="delete-apikey-btn"
                    title="Delete API key"
                    outline
                    color="danger"
                    className="border border-dark"
                    Icon={VscDebugDisconnect}
                    onClick={deleteTokenCb}
                  />
                </ButtonGroup>
              </ContentSection>
            </Col>
          </Row>
        </>
      )}
      // Error render (we catch 404 which means no API key exists)
      renderError={({ error }) =>
        error?.response?.status === 404 ? (
          <Alert color="dark" className="col-md-6 col-lg-3 mx-auto text-center">
            <h5 className="text-warning">No active API key</h5>
            <IconButton
              id="create-apikey-btn"
              color="tertiary"
              title="Click to generate new API key"
              titlePlacement="bottom"
              size="sm"
              Icon={GenerateIcon}
              onClick={createTokenCb}
            />
          </Alert>
        ) : (
          <ErrorAlert error={error} />
        )
      }
    />
  );
}
