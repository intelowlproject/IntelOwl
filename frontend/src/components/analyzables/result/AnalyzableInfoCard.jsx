import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  ListGroup,
  ListGroupItem,
  Badge,
  Collapse,
  Row,
  Col,
  UncontrolledTooltip,
} from "reactstrap";
import { VscGlobe, VscFile } from "react-icons/vsc";

import {
  ContentSection,
  CopyToClipboardButton,
  ArrowToggleIcon,
} from "@certego/certego-ui";

import { Classifications } from "../../../constants/miscConst";

export function AnalyzableInfoCard({ analyzable }) {
  // local state
  const [isOpenAnalyzableInfoCard, setIsOpenAnalyzableInfoCard] =
    React.useState(analyzable.classification === Classifications.FILE);

  return (
    <div id="AnalyzableInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center align-items-center offset-1"
            sm={12}
            md={10}
          >
            <h3 className="d-flex-start text-truncate">
              {analyzable.classification === Classifications.FILE ? (
                <VscFile className="me-1" />
              ) : (
                <VscGlobe className="me-1" />
              )}
              <CopyToClipboardButton
                showOnHover
                id="analyzable_name"
                text={analyzable.name}
              >
                {analyzable.name}
              </CopyToClipboardButton>
            </h3>
            <div className="h-100 d-flex align-items-start">
              <Badge className="ms-1 float-end" color="info">
                {analyzable.classification === Classifications.FILE
                  ? `file: ${analyzable.mimetype}`
                  : analyzable.classification}
              </Badge>
            </div>
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() =>
                setIsOpenAnalyzableInfoCard(!isOpenAnalyzableInfoCard)
              }
              id="AnalyzableInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpenAnalyzableInfoCard} />
            </Button>
            <UncontrolledTooltip
              placement="left"
              target="AnalyzableInfoCardDropDown"
            >
              Toggle Analyzable Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpenAnalyzableInfoCard} id="JobInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["SHA256", analyzable.sha256],
              ["SHA1", analyzable.sha1],
              ["MD5", analyzable.md5],
            ].map(([key, value]) => (
              <ListGroupItem className="mx-2" key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1 text-light">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
        </ContentSection>
      </Collapse>
    </div>
  );
}

AnalyzableInfoCard.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
