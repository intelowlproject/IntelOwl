import React from "react";
import { Row, Col, Badge } from "reactstrap";
import { VscDebugDisconnect } from "react-icons/vsc";

import {
  IconButton,
  MomentHoverable,
  useAxiosComponentLoader
} from "@certego/certego-ui";

import { SESSIONS_BASE_URI, deleteTokenById } from "./api";

export default function SessionsList() {
  console.debug("SessionsList rendered!");

  // API
  const [tokenSessions, Loader, refetch] = useAxiosComponentLoader(
    {
      url: SESSIONS_BASE_URI,
    },
    (respData) =>
      respData.sort((a, b) => !a.is_current || a.created - b.created)
  );

  // callbacks
  const revokeSessionCb = React.useCallback(
    async (id, clientName) => {
      try {
        await deleteTokenById(id, clientName);
        // reload after 500ms
        setTimeout(refetch, 500);
      } catch (e) {
        // handled inside deleteTokenById
      }
    },
    [refetch]
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
                    <small className="text-muted mr-1">Device</small>
                    &nbsp;
                    {client}
                  </Col>
                  <Col sm={6} xl={4}>
                    <small className="text-muted mr-1">Created</small>
                    <MomentHoverable
                      id={`sessionslist-${id}__created`}
                      value={created}
                      format="h:mm A MMM Do, YYYY"
                      title="Session create date"
                      showAgo
                    />
                  </Col>
                  <Col sm={6} xl={3}>
                    <small className="text-muted mr-1">Expires</small>
                    <MomentHoverable
                      id={`sessionslist-${id}__expires`}
                      value={expiry}
                      title="Session expiry date"
                      fromNow
                    />
                    {hasExpired && (
                      <Badge color="danger" className="ml-2">
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
            )
          )}
        </ol>
      )}
    />
  );
}
