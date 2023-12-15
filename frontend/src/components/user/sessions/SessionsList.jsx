import React from "react";
import { Row, Col, Badge } from "reactstrap";
import { VscDebugDisconnect } from "react-icons/vsc";

import {
  IconButton,
  DateHoverable,
  useAxiosComponentLoader,
} from "@certego/certego-ui";

import { SESSIONS_BASE_URI, deleteTokenById } from "./sessionApi";

export default function SessionsList() {
  console.debug("SessionsList rendered!");

  // API
  const [tokenSessions, Loader, refetch] = useAxiosComponentLoader(
    {
      url: SESSIONS_BASE_URI,
    },
    (respData) =>
      respData.sort(
        (currentSession, nextSession) =>
          !currentSession.is_current ||
          currentSession.created - nextSession.created,
      ),
  );

  // callbacks
  const revokeSessionCb = React.useCallback(
    async (id, clientName) => {
      try {
        await deleteTokenById(id, clientName);
        // reload after 500ms
        setTimeout(refetch, 500);
      } catch (error) {
        // handled inside deleteTokenById
      }
    },
    [refetch],
  );

  return (
    <Loader
      render={() => (
        <ol>
          {tokenSessions.map(
            ({
              id,
              client,
              created,
              expiry,
              has_expired: hasExpired,
              is_current: isCurrent,
            }) => (
              <li key={`sessionslist-${id}`}>
                <Row className="mb-3 d-flex flex-wrap">
                  <Col sm={6} xl={4}>
                    <small className="text-muted me-1">Device</small>
                    &nbsp;
                    {client}
                  </Col>
                  <Col sm={6} xl={4}>
                    <small className="text-muted me-1">Created</small>
                    <DateHoverable
                      id={`sessionslist-${id}__created`}
                      value={created}
                      format="hh:mm a MMM do, yyyy"
                      title="Session create date"
                      showAgo
                    />
                  </Col>
                  <Col sm={6} xl={3}>
                    <small className="text-muted me-1">Expires</small>
                    <DateHoverable
                      id={`sessionslist-${id}__expires`}
                      value={expiry}
                      title="Session expiry date"
                      format="hh:mm a MMM do, yyyy"
                      showAgo
                    />
                    {hasExpired && (
                      <Badge color="danger" className="ms-2">
                        expired
                      </Badge>
                    )}
                  </Col>
                  {/* Actions */}
                  <Col sm={6} xl={1} className="text-center">
                    {!isCurrent ? (
                      <IconButton
                        id={`sessionslist-${id}__revoke-btn`}
                        title="Revoke Session"
                        color="danger"
                        outline
                        size="xs"
                        Icon={VscDebugDisconnect}
                        onClick={() => revokeSessionCb(id, client)}
                      />
                    ) : (
                      <Badge color="info">current</Badge>
                    )}
                  </Col>
                </Row>
              </li>
            ),
          )}
        </ol>
      )}
    />
  );
}
