import React from "react";
import PropTypes from "prop-types";
import md5 from "md5";
import { useNavigate } from "react-router-dom";
import { Card, CardHeader, CardBody } from "reactstrap";
import { useAxiosComponentLoader, DateHoverable } from "@certego/certego-ui";
import {
  JOB_RECENT_SCANS,
  JOB_RECENT_SCANS_USER,
} from "../../../constants/api";

function RecentScansCard({
  pk,
  title,
  importance,
  playbook,
  finished,
  tlp,
  user,
}) {
  const navigate = useNavigate();
  const onClick = React.useCallback(
    (jobId) => {
      navigate(`/jobs/${jobId}`);
    },
    [navigate],
  );

  return (
    <Card
      id={`RecentScanCard-${pk}`}
      className="border-dark mb-2 pointer"
      onClick={() => onClick(pk)}
    >
      <CardHeader className="d-flex justify-content-between mx-3 bg-dark text-center p-0">
        <span className="text-truncate" style={{ maxWidth: "75%" }}>
          {title}
        </span>
        <small className="pt-1 text-secondary" style={{ fontSize: "0.75rem" }}>
          score: {importance}
        </small>
      </CardHeader>
      <CardBody
        className="d-flex bg-darker p-2 px-4"
        style={{
          borderBottomLeftRadius: "0.75rem",
          borderBottomRightRadius: "0.75rem",
        }}
      >
        <div className="d-flex flex-column col-8 px-2">
          <small>
            Playbook:{" "}
            <small className="text-accent">
              {playbook || "Custom analysis"}
            </small>
          </small>
          <small>
            Finished:{" "}
            <small>
              <DateHoverable
                className="text-accent"
                ago
                value={finished}
                format="hh:mm:ss a MMM do, yyyy"
              />
            </small>
          </small>
        </div>
        <div className="d-flex flex-column col-4">
          <small>
            TLP: <small className="text-accent">{tlp}</small>
          </small>
          <small>
            User: <small className="text-accent">{user}</small>
          </small>
        </div>
      </CardBody>
    </Card>
  );
}

RecentScansCard.propTypes = {
  pk: PropTypes.number.isRequired,
  title: PropTypes.string.isRequired,
  importance: PropTypes.number.isRequired,
  playbook: PropTypes.string,
  finished: PropTypes.any.isRequired,
  tlp: PropTypes.string.isRequired,
  user: PropTypes.string.isRequired,
};

RecentScansCard.defaultProps = {
  playbook: null,
};

export default function RecentScans({ classification, param }) {
  // user recent scans
  const [recentScansUser, LoaderRecentScansUser] = useAxiosComponentLoader({
    url: JOB_RECENT_SCANS_USER,
    method: "POST",
  });
  console.debug("recentScansUser", recentScansUser);
  // file md5
  const [fileMd5, setFileMd5] = React.useState("");
  if (classification === "file" && param) {
    param.text().then((x) => setFileMd5(md5(x)));
  }
  // observable/file recent scans
  const [recentScans, LoaderRecentScans] = useAxiosComponentLoader({
    url: JOB_RECENT_SCANS,
    method: "POST",
    data: { md5: fileMd5.length ? fileMd5 : md5(param) },
  });
  console.debug("recentScans", recentScans);

  const allRecentScans = recentScans.length
    ? recentScans.concat(recentScansUser)
    : recentScansUser;
  console.debug("allRecentScans", allRecentScans);

  return (
    <LoaderRecentScansUser
      render={() => (
        <div>
          <div className="d-flex justify-content-between my-3 align-items-end">
            <h5 className="fw-bold mb-0">Recent Scans</h5>
            <small className="mx-2 text-gray">
              {allRecentScans?.length} total
            </small>
          </div>
          <LoaderRecentScans
            render={() => (
              <div style={{ maxHeight: "500px", overflowY: "auto" }}>
                {allRecentScans.length ? (
                  allRecentScans.map((recentScan) => (
                    <RecentScansCard
                      pk={recentScan.pk}
                      title={recentScan.file_name || recentScan.observable_name}
                      importance={recentScan.importance}
                      playbook={recentScan.playbook}
                      finished={recentScan.finished_analysis_time}
                      tlp={recentScan.tlp}
                      user={recentScan.user}
                    />
                  ))
                ) : (
                  <small className="text-gray">No recent scans available</small>
                )}
              </div>
            )}
          />
        </div>
      )}
    />
  );
}

RecentScans.propTypes = {
  classification: PropTypes.string.isRequired,
  param: PropTypes.any.isRequired,
};
