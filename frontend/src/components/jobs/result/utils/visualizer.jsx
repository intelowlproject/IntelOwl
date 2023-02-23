import React, { Fragment } from "react";
import PropTypes from "prop-types";
import { ContentSection } from "@certego/certego-ui";
import { Row } from "reactstrap";
import { VisualizerComponent } from "./visualizerComponents";

const mockedData = [
  { name: "scanner", value: true, type: "bool", level: 1 },
  { name: "spammer", value: true, type: "bool", level: 1 },
  { name: "phishing", value: false, type: "bool", level: 1 },
  { name: "scammer", value: false, type: "bool", level: 1 },
  { name: "sinkhole", value: false, type: "bool", level: 1 },
  { name: "tor exit node", value: false, type: "bool", level: 1 },
  { name: "google malicious", value: false, type: "bool", level: 1 },
  { name: "quad9 malicious", value: true, type: "bool", level: 1 },
  { name: "tranco rank", value: 121233, type: "int", level: 1 },
  {
    name: "malware family",
    value: "mirai",
    type: "string",
    level: 1,
    additional_config: { link: "https://malpedia.caad.fkie.fraunhofer.de/" },
  },
  {
    name: "kill chain phase",
    value: "dropzone",
    type: "string",
    level: 1,
    additional_config: { link: "https://attack.mitre.org/" },
  },
  { name: "creation date", value: "2006-07-02", type: "string", level: 3 },
  { name: "country", value: "italy", type: "string", level: 3 },
  {
    name: "urls",
    value: [
      { value: "http://test.com/1" },
      { value: "http://test.com/2" },
      { value: "http://test.com/3" },
      { value: "http://test.com/4" },
      { value: "http://test.com/5" },
      { value: "http://test.com/6" },
      { value: "http://test.com/7" },
      { value: "http://test.com/8" },
      { value: "http://test.com/9" },
    ],
    type: "list",
    level: 2,
  },
  {
    name: "md5s",
    value: [
      { value: "11d5c09dfab9e17f0e3870af9c9961e8" },
      { value: "22d5c09dfab9e17f0e3870af9c9961e8" },
      { value: "33d5c09dfab9e17f0e3870af9c9961e8" },
    ],
    type: "list",
    level: 2,
  },
  {
    name: "general evaluation",
    value: "malicious",
    type: "str",
    level: 0,
    additional_config: { value_color: "danger" },
  },
  { name: "reliability", value: "B", type: "str", level: 0 },
  { name: "active resolution", value: "dns.google.com", type: "str", level: 3 },
  { name: "last resolution", value: "dns.google.com", type: "str", level: 3 },
  { name: " cloudflare malicious", value: true, type: "bool", level: 2 },
  {
    name: "passive DNS",
    value: [{ value: "dns.google.com" }, { value: "dns2.google.com" }],
    type: "list",
    level: 3,
  },
  { name: "another list (to hide)", value: [], type: "list", level: 3 },
  { name: "string (to hide)", value: "", type: "str", level: 3 },
  { name: "bool (to hide)", value: false, type: "bool", level: 3 },
];

function levelGenerator(data, levelSize) {
  // sort the element by type, in this way fields with the same type are groupped.
  data.sort((firstField, secondField) =>
    firstField.type > secondField.type ? 1 : -1
  );
  // size is calculated adding the levelSize to the tag "h". ex: levelSize = 3 => h3.
  return (
    <Row className={`justify-content-around align-items-center h${levelSize}`}>
      {data.map((field) => (
        <VisualizerComponent
          fieldName={field.name}
          fieldType={field.type}
          fieldValue={field.value}
          additionalConfig={field.additional_config}
          hideFalseValue
        />
      ))}
    </Row>
  );
}

export default function VisualizerReport({ job }) {
  console.debug("VisualizerReport rendered");
  console.debug("visualizer job");
  console.debug(job);

  let levelPositionList = mockedData.map((element) => element.level);
  levelPositionList = levelPositionList
    .filter((element, index) => levelPositionList.indexOf(element) === index)
    .sort();

  return (
    <ContentSection className="bg-body">
      {levelPositionList.map((levelPosition, index) => {
        let levelSize = index * 2 + 3;
        if (levelSize > 6) {
          levelSize = 6;
        }
        return (
          <Fragment>
            {levelGenerator(
              mockedData.filter((field) => field.level === levelPosition),
              levelSize
            )}
            {index + 1 !== levelPositionList.length && (
              <hr className="border-gray flex-grow-1" />
            )}
          </Fragment>
        );
      })}
    </ContentSection>
  );
}

VisualizerReport.propTypes = {
  job: PropTypes.object.isRequired,
};
