import React, { useState, useEffect } from "react";
import { Row, Col, Card, CardHeader, CardBody, Badge, ListGroup, ListGroupItem } from "reactstrap";
import { JobStatusBarChart, JobTopPlaybookBarChart } from "./charts";
import { WEBSOCKET_JOBS_URI } from "../../constants/apiURLs";
import { StatusColors, TLPColors } from "../../constants/colorConst";
import { useAuthStore } from "../../stores/useAuthStore";
import { JobFinalStatuses, JobStatuses } from "../../constants/jobConst";
import { TLPTag } from "../common/TLPTag";
import { Link } from "react-router-dom";

export const LiveThreatDashboard = ({ orgName }) => {
  const [activeJobsCount, setActiveJobsCount] = useState(0);
  const [liveFeed, setLiveFeed] = useState([]);
  const [activeJobIds, setActiveJobIds] = useState(new Set());
  const { isAuthenticated } = useAuthStore(
    React.useCallback((state) => ({ isAuthenticated: state.isAuthenticated }), [])
  );

  useEffect(() => {
    let ws = null;

    const connectWebSocket = () => {
      let wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      let wsUrl = `${wsProtocol}//${window.location.host}/${WEBSOCKET_JOBS_URI}/all`;

      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log("Connected to Live Threat WebSocket");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data && data.status) {
            const isFinal = Object.values(JobFinalStatuses).includes(data.status);
            const jobId = data.id;

            setActiveJobIds((prev) => {
              const next = new Set(prev);
              if (!isFinal) {
                next.add(jobId);
              } else {
                next.delete(jobId);
              }
              return next;
            });

            if (isFinal) {
              if (data.tlp === "AMBER" || data.tlp === "RED") {
                setLiveFeed((prev) => {
                  const updated = [data, ...prev];
                  const unique = Array.from(new Map(updated.map((item) => [item.id, item])).values());
                  return unique.slice(0, 20);
                });
              }
            }
          }
        } catch (err) {
          console.error("Error parsing websocket message", err);
        }
      };

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
      };
    };

    if (isAuthenticated) {
        connectWebSocket();
    }

    return () => {
      if (ws) ws.close();
    };
  }, [isAuthenticated]);

  useEffect(() => {
    setActiveJobsCount(activeJobIds.size);
  }, [activeJobIds]);

  return (
    <div className="mb-4">
      <Row className="mb-3 d-flex flex-wrap flex-lg-nowrap">
        <Col md={12} lg={4}>
          <Card className="text-center shadow-sm h-100 border-primary" style={{ minHeight: "250px" }}>
            <CardBody className="d-flex flex-column justify-content-center">
              <h5 className="text-muted fw-bold">Live Active Jobs Stream</h5>
              <h1 className="display-4 fw-bold text-primary">{activeJobsCount}</h1>
              <small className="text-muted">Jobs currently analyzing in real-time</small>
            </CardBody>
          </Card>
        </Col>
        <Col md={12} lg={8} className="mt-3 mt-lg-0">
          <Card className="shadow-sm h-100 border-danger" style={{ minHeight: "250px" }}>
            <CardHeader className="bg-transparent fw-bold border-bottom-0 text-danger">
              Live Feed: High Severity (AMBER / RED) Completed Jobs
            </CardHeader>
            <CardBody className="p-0" style={{ maxHeight: "200px", overflowY: "auto" }}>
              <ListGroup flush>
                {liveFeed.length === 0 ? (
                  <ListGroupItem className="text-center text-muted py-4 border-0">
                    Watching for new high severity jobs...
                  </ListGroupItem>
                ) : (
                  liveFeed.map((job) => (
                    <ListGroupItem key={job.id} className="d-flex justify-content-between align-items-center">
                      <div className="d-flex align-items-center">
                        <TLPTag tlp={job.tlp} />
                        <span className="ms-3 fw-bold">
                          <Link to={`/jobs/${job.id}`}>{job.name || `Job #${job.id}`}</Link>
                        </span>
                      </div>
                      <Badge color={StatusColors[job.status] || "secondary"} className="text-uppercase text-white">
                        {job.status}
                      </Badge>
                    </ListGroupItem>
                  ))
                )}
              </ListGroup>
            </CardBody>
          </Card>
        </Col>
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        <Col key="LiveJobStatusBarChart" md={12} lg={6}>
          <Card className="shadow-sm h-100">
             <CardHeader className="bg-transparent fw-bold border-bottom-0">24h Threat Severity Distribution</CardHeader>
             <CardBody style={{ minHeight: "360px" }}>
                 <JobStatusBarChart orgName={orgName} />
             </CardBody>
          </Card>
        </Col>
        <Col key="LiveJobTopPlaybookBarChart" md={12} lg={6} className="mt-3 mt-lg-0">
          <Card className="shadow-sm h-100">
             <CardHeader className="bg-transparent fw-bold border-bottom-0">Top Triggered Analyzers (24h)</CardHeader>
             <CardBody style={{ minHeight: "360px" }}>
                 <JobTopPlaybookBarChart orgName={orgName} />
             </CardBody>
          </Card>
        </Col>
      </Row>
    </div>
  );
};
