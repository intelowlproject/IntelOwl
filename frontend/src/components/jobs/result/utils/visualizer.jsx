import React from "react";
import PropTypes from "prop-types";
import { ContentSection } from "@certego/certego-ui";
import {
    Row,
} from "reactstrap";
import { StringVisualizerField, BooleanVisualizerField } from "./visualizerComponents";


const mockedData = [
    {name: "evaluation", value: "malicious", type: "str", level: 0},
    {name: "reliability", value: "B", type: "str", level: 0},
    {name: "is_scanner", value: true, type: "bool", level: 1},
    {name: "is_spammer", value: true, type: "bool", level: 1},
    {name: "is_phishing", value: false, type: "bool", level: 1},
    {name: "is_scammer", value: false, type: "bool", level: 1},
    {name: "is_sinkhole", value: false, type: "bool", level: 1},
    {name: "is_tor_exit_node", value: false, type: "bool", level: 1},
    {name: "is_google_malicious", value: false, type: "bool", level: 1},
    {name: "is_cloudflare_malicious", value: true, type: "bool", level: 1},
    {name: "is_quad9_malicious", value: true, type: "bool", level: 1},
    {name: "tranco_rank", value: 121233, type: "int", level: 1},
    {name: "urls", value: ["http://test.com/1", "http://test.com/2", "http://test.com/3"], type: "list", level: 1},
    {name: "md5s", value: ["11d5c09dfab9e17f0e3870af9c9961e8", "22d5c09dfab9e17f0e3870af9c9961e8", "33d5c09dfab9e17f0e3870af9c9961e8"], type: "int", level: 1},
]

function componentConverter(fieldType) {
    switch(fieldType) {
        case 'bool':
            return BooleanVisualizerField;
        default:
            return StringVisualizerField;
    };
}

function levelGenerator(data, levelValue) {
    /* level 0 = h3. If we want to decrease the size for each level we simply increase the h value:
    lv 1 = h4 (3+1), lv2 = h5(3+2).
    */
    const levelSize = `h${4 + levelValue}`;
    return (
        <Row horizontal className={`justify-content-around ${levelSize}`}>
            {data.filter(field => field.level === levelValue).map(field => {
                const Component = componentConverter(field.type);
                return <Component key={field.name} fieldName={field.name} fieldValue={field.value} />;
            })}
        </Row>
    );
}

export default function VisualizerReport({ job }) {
    console.debug("visualizer job")
    console.debug(job)
    return (
        <ContentSection className="bg-body">
            {levelGenerator(mockedData, 0)}
            <hr className="border-gray flex-grow-1" />
            {levelGenerator(mockedData, 1)}
        </ContentSection>
    )
}

VisualizerReport.propTypes = {
    job: PropTypes.object.isRequired,
};
