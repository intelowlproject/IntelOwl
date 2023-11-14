import React from "react";
import { UncontrolledPopover, Card, CardHeader, CardBody } from "reactstrap";
import { MdInfo } from "react-icons/md";
import PropTypes from "prop-types";

function PlaybookExecutedInfoCard({ job }) {
  console.debug(job);
  return (
    <Card className="border-dark p-0">
      <CardHeader className="d-flex align-items-center bg-body p-2 h6">
        <span>{job.playbook_to_execute || "Custom analysis"}</span>
      </CardHeader>
      <CardBody className="bg-darker border-top border-tertiary">
        <div className="d-flex flex-column justify-content-center">
          <span>{job.analyzers_to_execute.length} analyzers</span>
          <span>{job.connectors_to_execute.length} connectors</span>
          <span>{job.pivots_to_execute.length} pivots</span>
          <span>{job.visualizers_to_execute.length} visualizers</span>
        </div>
      </CardBody>
    </Card>
  );
}

export function PlaybookInfoPopoverIcon({ job }) {
  return (
    <div>
      <MdInfo
        id={`jobtable-infoicon__job-${job.id}`}
        className="text-info"
        fontSize="20"
      />
      <UncontrolledPopover
        trigger="hover"
        delay={{ show: 0, hide: 500 }}
        target={`jobtable-infoicon__job-${job.id}`}
      >
        <PlaybookExecutedInfoCard job={job} />
      </UncontrolledPopover>
    </div>
  );
}

PlaybookExecutedInfoCard.propTypes = {
  job: PropTypes.object.isRequired,
};

PlaybookInfoPopoverIcon.propTypes = {
  job: PropTypes.object.isRequired,
};
