import React from "react";
import { useSearchParams, Link } from "react-router-dom";
import {
  Container,
  Row,
  Col,
  Card,
  CardHeader,
  CardBody,
  Button,
  Input,
  Badge,
  Alert,
  ButtonGroup,
} from "reactstrap";
import {
  MdCompareArrows,
  MdSwapHoriz,
  MdExpandMore,
  MdExpandLess,
  MdCheckCircle,
  MdWarning,
  MdInfo,
  MdHelpOutline,
} from "react-icons/md";
import useTitle from "react-use/lib/useTitle";
import {
  Loader,
  DateHoverable,
  CopyToClipboardButton,
} from "@certego/certego-ui";

import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { JsonEditor } from "../../common/JsonEditor";
import { fetchJobComparison } from "../result/jobApi";
import { JobResultSections } from "../../../constants/miscConst";
import { processTimeMMSS } from "../../../utils/time";

export default function JobCompare() {
  useTitle("IntelOwl | Job Comparison", { restoreOnUnmount: true });

  const [searchParams, setSearchParams] = useSearchParams();
  const paramJobA = searchParams.get("id1") || searchParams.get("job_a") || "";
  const paramJobB = searchParams.get("id2") || searchParams.get("job_b") || "";

  const [inputJobA, setInputJobA] = React.useState(paramJobA);
  const [inputJobB, setInputJobB] = React.useState(paramJobB);
  const [comparisonData, setComparisonData] = React.useState(null);
  const [isLoading, setIsLoading] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState(null);

  const [filterType, setFilterType] = React.useState("all");
  const [searchQuery, setSearchQuery] = React.useState("");
  const [expandedAnalyzers, setExpandedAnalyzers] = React.useState({});

  // Sync inputs with URL params
  React.useEffect(() => {
    setInputJobA(paramJobA);
    setInputJobB(paramJobB);
  }, [paramJobA, paramJobB]);

  // Load comparison data when URL params change
  React.useEffect(() => {
    let isMounted = true;

    if (!paramJobA || !paramJobB) {
      setComparisonData(null);
      setErrorMessage(null);
    } else {
      setIsLoading(true);
      setErrorMessage(null);

      fetchJobComparison(paramJobA, paramJobB)
        .then((data) => {
          if (!isMounted) return;
          setComparisonData(data);
          setIsLoading(false);
        })
        .catch((error) => {
          if (!isMounted) return;
          const detail =
            error.response?.data?.detail ||
            error.message ||
            "Failed to load comparison data.";
          setErrorMessage(detail);
          setIsLoading(false);
        });
    }

    return () => {
      isMounted = false;
    };
  }, [paramJobA, paramJobB]);

  const handleSubmitComparison = (event) => {
    event.preventDefault();
    if (!inputJobA.trim() || !inputJobB.trim()) return;
    setSearchParams({
      id1: inputJobA.trim(),
      id2: inputJobB.trim(),
    });
  };

  const handleSwapJobs = () => {
    const tempJobA = inputJobA;
    setInputJobA(inputJobB);
    setInputJobB(tempJobA);
    if (paramJobA && paramJobB) {
      setSearchParams({
        id1: inputJobB,
        id2: tempJobA,
      });
    }
  };

  const toggleAnalyzerExpansion = (analyzerName) => {
    setExpandedAnalyzers((prev) => ({
      ...prev,
      [analyzerName]: !prev[analyzerName],
    }));
  };

  const setAllAnalyzersExpanded = (expandState) => {
    if (!comparisonData?.analyzers) return;
    const updatedState = {};
    comparisonData.analyzers.forEach((analyzer) => {
      updatedState[analyzer.name] = expandState;
    });
    setExpandedAnalyzers(updatedState);
  };

  // Filter analyzers based on active tab and search query
  const filteredAnalyzers = React.useMemo(() => {
    if (!comparisonData?.analyzers) return [];

    return comparisonData.analyzers.filter((analyzer) => {
      const matchesSearch = analyzer.name
        .toLowerCase()
        .includes(searchQuery.toLowerCase());
      if (!matchesSearch) return false;

      if (filterType === "diff") return analyzer.has_differences;
      if (filterType === "common") return analyzer.present_in === "both";
      if (filterType === "unique_a") return analyzer.present_in === "job_a";
      if (filterType === "unique_b") return analyzer.present_in === "job_b";
      return true;
    });
  }, [comparisonData, filterType, searchQuery]);

  return (
    <Container fluid className="px-3 px-md-4 py-2">
      {/* Top Header and Job Selection */}
      <Row className="mb-3 align-items-center">
        <Col xs={12} lg={4}>
          <h2 className="mb-1 d-flex align-items-center">
            <MdCompareArrows className="me-2 text-info" />
            Job Comparison
          </h2>
          <small className="text-muted">
            Side-by-side analysis, difference detection, and artifact inspection
          </small>
        </Col>

        <Col xs={12} lg={8} className="mt-2 mt-lg-0">
          <form
            onSubmit={handleSubmitComparison}
            className="d-flex flex-wrap align-items-center justify-content-lg-end gap-2"
          >
            <div className="d-flex align-items-center">
              <span className="me-2 fw-bold text-nowrap">Job A:</span>
              <Input
                type="number"
                placeholder="Job ID"
                value={inputJobA}
                onChange={(event) => setInputJobA(event.target.value)}
                style={{ width: "110px" }}
                required
              />
            </div>

            <Button
              type="button"
              color="secondary"
              outline
              onClick={handleSwapJobs}
              title="Swap Job A and Job B"
              className="px-2"
            >
              <MdSwapHoriz size={20} />
            </Button>

            <div className="d-flex align-items-center">
              <span className="me-2 fw-bold text-nowrap">Job B:</span>
              <Input
                type="number"
                placeholder="Job ID"
                value={inputJobB}
                onChange={(event) => setInputJobB(event.target.value)}
                style={{ width: "110px" }}
                required
              />
            </div>

            <Button type="submit" color="primary" className="ms-1">
              Compare
            </Button>
          </form>
        </Col>
      </Row>

      {/* Loading state */}
      {isLoading && (
        <div className="py-5 text-center">
          <Loader loading />
        </div>
      )}

      {/* Error state */}
      {errorMessage && !isLoading && (
        <Alert color="danger" className="my-3">
          <div className="d-flex align-items-center">
            <MdWarning className="me-2" size={24} />
            <span>{errorMessage}</span>
          </div>
        </Alert>
      )}

      {/* Empty prompt state */}
      {!paramJobA && !paramJobB && !isLoading && (
        <Card className="my-4 border-secondary text-center p-5 bg-dark">
          <CardBody>
            <MdHelpOutline size={56} className="text-muted mb-3" />
            <h4 className="text-light">Select Two Jobs to Compare</h4>
            <p className="text-muted mb-3">
              Enter two Job IDs above to inspect differences between analysis
              runs, track temporal changes, or compare malware variants.
            </p>
            <Button
              tag={Link}
              to="/history/jobs"
              color="outline-info"
              className="mt-2"
            >
              Browse Jobs History
            </Button>
          </CardBody>
        </Card>
      )}

      {/* Comparison Content */}
      {comparisonData && !isLoading && (
        <>
          {/* Observable Comparison Banner */}
          <Alert
            color={
              comparisonData.summary.same_observable ? "success" : "warning"
            }
            className="d-flex align-items-center justify-content-between mb-3 py-2 px-3"
          >
            <div className="d-flex align-items-center">
              {comparisonData.summary.same_observable ? (
                <>
                  <MdCheckCircle className="me-2" size={20} />
                  <span>
                    Comparing identical observable:{" "}
                    <strong>{comparisonData.job_a.observable_name}</strong> (
                    {comparisonData.job_a.observable_classification})
                  </span>
                </>
              ) : (
                <>
                  <MdInfo className="me-2" size={20} />
                  <span>
                    Cross-observable comparison:{" "}
                    <strong>{comparisonData.job_a.observable_name}</strong> vs{" "}
                    <strong>{comparisonData.job_b.observable_name}</strong>
                  </span>
                </>
              )}
            </div>

            <Badge color="dark" className="px-2 py-1 text-light">
              {comparisonData.summary.differing_analyzers_count} analyzer diffs
              detected
            </Badge>
          </Alert>

          {/* Metadata Cards Side-by-Side */}
          <Row className="mb-3 g-3">
            {/* Job A Card */}
            <Col xs={12} md={6}>
              <Card className="h-100 border-secondary">
                <CardHeader className="d-flex justify-content-between align-items-center bg-dark py-2">
                  <span className="fw-bold text-info">
                    Job #{comparisonData.job_a.id}
                  </span>
                  <div className="d-flex align-items-center gap-2">
                    <StatusTag status={comparisonData.job_a.status} />
                    <TLPTag value={comparisonData.job_a.tlp} />
                    <Link
                      to={`/jobs/${comparisonData.job_a.id}/${JobResultSections.VISUALIZER}`}
                      target="_blank"
                      className="btn btn-xs btn-outline-light ms-1"
                    >
                      View Report
                    </Link>
                  </div>
                </CardHeader>
                <CardBody className="py-2">
                  <div className="mb-1 text-truncate">
                    <span className="text-muted me-2">Observable:</span>
                    <CopyToClipboardButton
                      text={comparisonData.job_a.observable_name || ""}
                    >
                      <span className="fw-semibold">
                        {comparisonData.job_a.observable_name || "-"}
                      </span>
                    </CopyToClipboardButton>
                    <Badge color="secondary" className="ms-2">
                      {comparisonData.job_a.observable_classification ||
                        (comparisonData.job_a.is_sample ? "FILE" : "-")}
                    </Badge>
                  </div>

                  {comparisonData.job_a.md5 && (
                    <div className="mb-1 text-truncate">
                      <span className="text-muted me-2">MD5:</span>
                      <CopyToClipboardButton text={comparisonData.job_a.md5}>
                        <small className="font-monospace">
                          {comparisonData.job_a.md5}
                        </small>
                      </CopyToClipboardButton>
                    </div>
                  )}

                  <div className="d-flex justify-content-between text-muted small my-1">
                    <span>
                      Created:{" "}
                      {comparisonData.job_a.created_at ? (
                        <DateHoverable
                          value={comparisonData.job_a.created_at}
                          ago
                        />
                      ) : (
                        "-"
                      )}
                    </span>
                    <span>
                      Duration:{" "}
                      {comparisonData.job_a.process_time
                        ? processTimeMMSS(comparisonData.job_a.process_time)
                        : "-"}
                    </span>
                  </div>

                  {/* Tags */}
                  <div className="mt-2 pt-1 border-top border-secondary">
                    <small className="text-muted me-1">Tags:</small>
                    {comparisonData.job_a.tags.length > 0 ? (
                      comparisonData.job_a.tags.map((tagName) => {
                        const isShared =
                          comparisonData.summary.tag_diff.shared.includes(
                            tagName,
                          );
                        return (
                          <Badge
                            key={`tag-a-${tagName}`}
                            color={isShared ? "secondary" : "info"}
                            className="me-1 mb-1"
                          >
                            {tagName}
                          </Badge>
                        );
                      })
                    ) : (
                      <small className="text-muted">None</small>
                    )}
                  </div>
                </CardBody>
              </Card>
            </Col>

            {/* Job B Card */}
            <Col xs={12} md={6}>
              <Card className="h-100 border-secondary">
                <CardHeader className="d-flex justify-content-between align-items-center bg-dark py-2">
                  <span className="fw-bold text-info">
                    Job #{comparisonData.job_b.id}
                  </span>
                  <div className="d-flex align-items-center gap-2">
                    <StatusTag status={comparisonData.job_b.status} />
                    <TLPTag value={comparisonData.job_b.tlp} />
                    <Link
                      to={`/jobs/${comparisonData.job_b.id}/${JobResultSections.VISUALIZER}`}
                      target="_blank"
                      className="btn btn-xs btn-outline-light ms-1"
                    >
                      View Report
                    </Link>
                  </div>
                </CardHeader>
                <CardBody className="py-2">
                  <div className="mb-1 text-truncate">
                    <span className="text-muted me-2">Observable:</span>
                    <CopyToClipboardButton
                      text={comparisonData.job_b.observable_name || ""}
                    >
                      <span className="fw-semibold">
                        {comparisonData.job_b.observable_name || "-"}
                      </span>
                    </CopyToClipboardButton>
                    <Badge color="secondary" className="ms-2">
                      {comparisonData.job_b.observable_classification ||
                        (comparisonData.job_b.is_sample ? "FILE" : "-")}
                    </Badge>
                  </div>

                  {comparisonData.job_b.md5 && (
                    <div className="mb-1 text-truncate">
                      <span className="text-muted me-2">MD5:</span>
                      <CopyToClipboardButton text={comparisonData.job_b.md5}>
                        <small className="font-monospace">
                          {comparisonData.job_b.md5}
                        </small>
                      </CopyToClipboardButton>
                    </div>
                  )}

                  <div className="d-flex justify-content-between text-muted small my-1">
                    <span>
                      Created:{" "}
                      {comparisonData.job_b.created_at ? (
                        <DateHoverable
                          value={comparisonData.job_b.created_at}
                          ago
                        />
                      ) : (
                        "-"
                      )}
                    </span>
                    <span>
                      Duration:{" "}
                      {comparisonData.job_b.process_time
                        ? processTimeMMSS(comparisonData.job_b.process_time)
                        : "-"}
                    </span>
                  </div>

                  {/* Tags */}
                  <div className="mt-2 pt-1 border-top border-secondary">
                    <small className="text-muted me-1">Tags:</small>
                    {comparisonData.job_b.tags.length > 0 ? (
                      comparisonData.job_b.tags.map((tagName) => {
                        const isShared =
                          comparisonData.summary.tag_diff.shared.includes(
                            tagName,
                          );
                        return (
                          <Badge
                            key={`tag-b-${tagName}`}
                            color={isShared ? "secondary" : "info"}
                            className="me-1 mb-1"
                          >
                            {tagName}
                          </Badge>
                        );
                      })
                    ) : (
                      <small className="text-muted">None</small>
                    )}
                  </div>
                </CardBody>
              </Card>
            </Col>
          </Row>

          {/* Filter Bar and Actions */}
          <Card className="mb-3 border-secondary bg-dark">
            <CardBody className="py-2 d-flex flex-wrap align-items-center justify-content-between gap-2">
              <ButtonGroup size="sm">
                <Button
                  color={filterType === "all" ? "primary" : "outline-secondary"}
                  onClick={() => setFilterType("all")}
                >
                  All ({comparisonData.analyzers.length})
                </Button>
                <Button
                  color={
                    filterType === "diff" ? "warning" : "outline-secondary"
                  }
                  onClick={() => setFilterType("diff")}
                >
                  Differences (
                  {comparisonData.summary.differing_analyzers_count})
                </Button>
                <Button
                  color={
                    filterType === "common" ? "primary" : "outline-secondary"
                  }
                  onClick={() => setFilterType("common")}
                >
                  Common ({comparisonData.summary.common_analyzers_count})
                </Button>
                <Button
                  color={
                    filterType === "unique_a" ? "primary" : "outline-secondary"
                  }
                  onClick={() => setFilterType("unique_a")}
                >
                  Only in #{comparisonData.job_a.id} (
                  {comparisonData.summary.unique_analyzers_a_count})
                </Button>
                <Button
                  color={
                    filterType === "unique_b" ? "primary" : "outline-secondary"
                  }
                  onClick={() => setFilterType("unique_b")}
                >
                  Only in #{comparisonData.job_b.id} (
                  {comparisonData.summary.unique_analyzers_b_count})
                </Button>
              </ButtonGroup>

              <div className="d-flex align-items-center gap-2">
                <Input
                  type="text"
                  placeholder="Filter by analyzer name..."
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  style={{ width: "220px" }}
                  bsSize="sm"
                />
                <Button
                  size="sm"
                  color="secondary"
                  outline
                  onClick={() => setAllAnalyzersExpanded(true)}
                  title="Expand all analyzers"
                >
                  Expand All
                </Button>
                <Button
                  size="sm"
                  color="secondary"
                  outline
                  onClick={() => setAllAnalyzersExpanded(false)}
                  title="Collapse all analyzers"
                >
                  Collapse All
                </Button>
              </div>
            </CardBody>
          </Card>

          {/* Analyzers Comparison List */}
          <div className="d-flex flex-column gap-2 mb-4">
            {filteredAnalyzers.length === 0 ? (
              <Card className="border-secondary text-center p-4 bg-dark">
                <span className="text-muted">
                  No analyzers match current filter criteria.
                </span>
              </Card>
            ) : (
              filteredAnalyzers.map((analyzer) => {
                const isExpanded = !!expandedAnalyzers[analyzer.name];
                return (
                  <Card
                    key={`analyzer-${analyzer.name}`}
                    className="border-secondary"
                  >
                    {/* Header */}
                    <CardHeader
                      className="d-flex align-items-center justify-content-between py-2 px-3 bg-dark cursor-pointer"
                      onClick={() => toggleAnalyzerExpansion(analyzer.name)}
                      style={{ cursor: "pointer" }}
                    >
                      <div className="d-flex align-items-center gap-2">
                        {isExpanded ? (
                          <MdExpandLess size={22} />
                        ) : (
                          <MdExpandMore size={22} />
                        )}
                        <span className="fw-bold text-light">
                          {analyzer.name}
                        </span>

                        {/* Presence badge */}
                        {analyzer.present_in === "both" && (
                          <Badge color="secondary" className="px-2">
                            Both
                          </Badge>
                        )}
                        {analyzer.present_in === "job_a" && (
                          <Badge color="info" className="px-2">
                            Only Job #{comparisonData.job_a.id}
                          </Badge>
                        )}
                        {analyzer.present_in === "job_b" && (
                          <Badge color="warning" className="px-2">
                            Only Job #{comparisonData.job_b.id}
                          </Badge>
                        )}

                        {/* Difference badge */}
                        {analyzer.present_in === "both" &&
                          (analyzer.has_differences ? (
                            <Badge color="danger" className="px-2">
                              Differs
                            </Badge>
                          ) : (
                            <Badge color="success" className="px-2">
                              Identical
                            </Badge>
                          ))}
                      </div>

                      {/* Status summary */}
                      <div className="d-flex align-items-center gap-2">
                        <small className="text-muted">
                          A: {analyzer.status_a || "Not run"}
                        </small>
                        <span className="text-muted">|</span>
                        <small className="text-muted">
                          B: {analyzer.status_b || "Not run"}
                        </small>
                      </div>
                    </CardHeader>

                    {/* Body */}
                    {isExpanded && (
                      <CardBody className="p-3 bg-darker">
                        {/* Summary of differing keys */}
                        {analyzer.diff_summary && (
                          <div className="mb-2 p-2 rounded bg-dark border border-secondary small">
                            {analyzer.diff_summary.keys_differing.length >
                              0 && (
                              <div className="mb-1">
                                <span className="text-warning fw-semibold me-2">
                                  Modified fields:
                                </span>
                                {analyzer.diff_summary.keys_differing.map(
                                  (keyName) => (
                                    <Badge
                                      key={`diff-${keyName}`}
                                      color="warning"
                                      className="me-1"
                                    >
                                      {keyName}
                                    </Badge>
                                  ),
                                )}
                              </div>
                            )}
                            {analyzer.diff_summary.keys_only_in_a.length >
                              0 && (
                              <div className="mb-1">
                                <span className="text-info fw-semibold me-2">
                                  Only in Job #{comparisonData.job_a.id}:
                                </span>
                                {analyzer.diff_summary.keys_only_in_a.map(
                                  (keyName) => (
                                    <Badge
                                      key={`only-a-${keyName}`}
                                      color="info"
                                      className="me-1"
                                    >
                                      {keyName}
                                    </Badge>
                                  ),
                                )}
                              </div>
                            )}
                            {analyzer.diff_summary.keys_only_in_b.length >
                              0 && (
                              <div>
                                <span className="text-info fw-semibold me-2">
                                  Only in Job #{comparisonData.job_b.id}:
                                </span>
                                {analyzer.diff_summary.keys_only_in_b.map(
                                  (keyName) => (
                                    <Badge
                                      key={`only-b-${keyName}`}
                                      color="info"
                                      className="me-1"
                                    >
                                      {keyName}
                                    </Badge>
                                  ),
                                )}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Side by side JSON Reports */}
                        <Row className="g-3">
                          {/* Column A */}
                          <Col xs={12} md={6}>
                            <div className="p-2 border border-secondary rounded">
                              <div className="d-flex justify-content-between align-items-center mb-2">
                                <span className="fw-semibold text-info small">
                                  Job #{comparisonData.job_a.id} (
                                  {analyzer.name})
                                </span>
                                {analyzer.status_a && (
                                  <StatusTag status={analyzer.status_a} />
                                )}
                              </div>

                              {analyzer.errors_a &&
                                analyzer.errors_a.length > 0 && (
                                  <Alert
                                    color="danger"
                                    className="py-1 px-2 small mb-2"
                                  >
                                    {analyzer.errors_a.join(", ")}
                                  </Alert>
                                )}

                              {analyzer.report_a ? (
                                <JsonEditor
                                  id={`compare-a-${analyzer.name}`}
                                  initialJsonData={analyzer.report_a}
                                  height="320px"
                                  readOnly
                                />
                              ) : (
                                <div className="text-muted text-center py-4 small">
                                  No report available for Job #
                                  {comparisonData.job_a.id}
                                </div>
                              )}
                            </div>
                          </Col>

                          {/* Column B */}
                          <Col xs={12} md={6}>
                            <div className="p-2 border border-secondary rounded">
                              <div className="d-flex justify-content-between align-items-center mb-2">
                                <span className="fw-semibold text-info small">
                                  Job #{comparisonData.job_b.id} (
                                  {analyzer.name})
                                </span>
                                {analyzer.status_b && (
                                  <StatusTag status={analyzer.status_b} />
                                )}
                              </div>

                              {analyzer.errors_b &&
                                analyzer.errors_b.length > 0 && (
                                  <Alert
                                    color="danger"
                                    className="py-1 px-2 small mb-2"
                                  >
                                    {analyzer.errors_b.join(", ")}
                                  </Alert>
                                )}

                              {analyzer.report_b ? (
                                <JsonEditor
                                  id={`compare-b-${analyzer.name}`}
                                  initialJsonData={analyzer.report_b}
                                  height="320px"
                                  readOnly
                                />
                              ) : (
                                <div className="text-muted text-center py-4 small">
                                  No report available for Job #
                                  {comparisonData.job_b.id}
                                </div>
                              )}
                            </div>
                          </Col>
                        </Row>
                      </CardBody>
                    )}
                  </Card>
                );
              })
            )}
          </div>
        </>
      )}
    </Container>
  );
}
