import React from "react";
import PropTypes from "prop-types";
import md5 from "md5";
import { useNavigate } from "react-router-dom";
import { Card, CardHeader, CardBody } from "reactstrap";
import { DateHoverable, Loader } from "@certego/certego-ui";
import useRecentScansStore from "../../../stores/useRecentScansStore";

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
  // api
  const [
    loadingScansUser,
    loadingScansInsertedAnalyzable,
    recentScansUserError,
    recentScansError,
    recentScansUser,
    recentScans,
    fetchRecentScansUser,
    fetchRecentscans,
  ] = useRecentScansStore((state) => [
    state.loadingScansUser,
    state.loadingScansInsertedAnalyzable,
    state.recentScansUserError,
    state.recentScansError,
    state.recentScansUser,
    state.recentScans,
    state.fetchRecentScansUser,
    state.fetchRecentscans,
  ]);

  console.debug(
    "loadingScansUser",
    loadingScansUser,
    "loadingScans",
    loadingScansInsertedAnalyzable,
  );

  // file md5
  const [fileMd5, setFileMd5] = React.useState("");
  if (classification === "file" && param) {
    param.text().then((x) => setFileMd5(md5(x)));
  }

  React.useEffect(() => {
    fetchRecentScansUser();
  }, [fetchRecentScansUser]);
  console.debug("recentScansUser", recentScansUser);

  React.useEffect(() => {
    fetchRecentscans(fileMd5.length ? fileMd5 : md5(param));
  }, [fetchRecentscans, fileMd5, param]);
  console.debug("recentScans", recentScans);

  // remove duplicate job
  const allRecentScans = Array.from(
    [...recentScans, ...recentScansUser]
      .reduce((m, scan) => m.set(scan.pk, scan), new Map())
      .values(),
  );
  console.debug("allRecentScans", allRecentScans);

  return (
    <Loader
      loading={loadingScansUser}
      error={recentScansUserError}
      render={() => (
        <div>
          <div className="d-flex justify-content-between my-3 align-items-end">
            <h5 className="fw-bold mb-0">Recent Scans</h5>
            <small className="mx-2 text-gray">
              {allRecentScans?.length} total
            </small>
          </div>
          <Loader
            loading={loadingScansInsertedAnalyzable}
            error={recentScansError}
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
  param: PropTypes.any,
};

RecentScans.defaultProps = {
  param: "",
};
