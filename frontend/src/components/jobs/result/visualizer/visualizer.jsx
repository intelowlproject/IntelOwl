import React, { Fragment } from "react";
import PropTypes from "prop-types";
import { ContentSection } from "@certego/certego-ui";
import { Row } from "reactstrap";

import { visualizerValidator } from "./validators";

import { BooleanVisualizer } from "./elements/bool";
import { BaseVisualizer } from "./elements/base";
import { ListVisualizer } from "./elements/list";
import { IconVisualizer } from "./elements/icon";
import { TitleVisualizer } from "./elements/title";

import { VisualizerComponentType } from "./elements/const";

// test data (list of levels)
const mockedData = [
  {
    level: 3,
    elements: [
      {
        type: "title",
        title: "disable title",
        value: "",
        disable_if_empty: true,
      },
      {
        type: "bool",
        name: "disable bool",
        value: false,
        pill: true,
        disable_if_empty: true,
      },
      {
        type: "base",
        name: "disable base",
        value: "",
        disable_if_empty: true,
      },
      {
        type: "icon",
        name: "disable icon",
        value: "",
        disable_if_empty: true,
      },
      {
        type: "list",
        name: "disable list",
        values: [],
        disable_if_empty: true,
      },
    ],
  },
  {
    level: 0,
    elements: [
      {
        type: "title",
        title: "title-title",
        value: "title-value",
      },
      {
        type: "bool",
        name: "base bool",
        value: true,
      },
      {
        type: "base",
        value: "base base",
      },
      {
        type: "icon",
        value: "gb",
        link: "https://otx.alienvault.com/",
      },
      {
        type: "list",
        name: "base list (2)",
        values: [
          { type: "base", value: "first elem" },
          { type: "base", value: "second elem" },
        ],
      },
    ],
  },
  // advanced (test all fields)
  {
    level: 1,
    elements: [
      {
        type: "title",
        title: "advanced title-title",
        value: "advanced title-value",
        title_color: "danger",
        title_link: "http://google.com",
        title_elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true, color: "success" },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
        title_classname: "border",
        value_color: "success",
        value_link: "http://apple.com",
        value_classname: "border",
        value_elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true, color: "success" },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
      },
      {
        type: "bool",
        name: "advanced bool",
        value: true,
        pill: false,
        link: "https://google.com",
        classname: "border",
        color: "success",
        elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
      },
      {
        type: "base",
        value: "advanced base",
        color: "danger",
        link: "http://google.com",
        classname: "border",
        elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true, color: "success" },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
      },
      {
        type: "icon",
        value: "otx",
        color: "success",
        link: "https://otx.alienvault.com/",
        classname: "border",
        elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true, color: "success" },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
      },
      {
        type: "list",
        name: "advanced list",
        values: [
          { type: "base", value: "1st" },
          { type: "bool", name: "2nd", value: true },
          { type: "title", title: "3rd", value: "val" },
          { type: "icon", value: "otx" },
          {
            type: "list",
            name: "5th",
            values: [
              { type: "base", value: "5.1th" },
              { type: "base", value: "5.2th" },
            ],
          },
        ],
        color: "warning",
        link: "https://google.com",
        classname: "border",
        open: true,
        elements: [
          {
            type: "base",
            value: "10",
            color: "primary",
            elements: [{ type: "base", value: "second lv" }],
          },
          { type: "icon", value: "otx" },
          { type: "title", title: "title", value: "value" },
          { type: "bool", name: "bool", value: true, color: "success" },
          {
            type: "list",
            name: "list (1)",
            values: [{ type: "base", value: "item" }],
          },
        ],
      },
    ],
  },
  // hide row
  {
    level: 2,
    elements: [
      {
        type: "title",
        title: "hide title",
        value: "",
        hide_if_empty: true,
        disable_if_empty: true,
      },
      {
        type: "bool",
        name: "hide bool",
        value: false,
        pill: true,
        hide_if_empty: true,
        disable_if_empty: true,
      },
      {
        type: "base",
        name: "hide base",
        value: "",
        hide_if_empty: true,
        disable_if_empty: true,
      },
      {
        type: "icon",
        name: "hide icon",
        value: "",
        hide_if_empty: true,
        disable_if_empty: true,
      },
      {
        type: "list",
        name: "hide list",
        values: [],
        hide_if_empty: true,
        disable_if_empty: true,
      },
    ],
  },
];

/**
 * Convert the validated data into a VisualizerElement.
 * This is a recursive function: It's called by the component to convert the inner components.
 *
 * @param {object} element data used to generate the component
 * @returns {React.Component} component to visualize
 */
function convertToElement(element) {
  // this is a function used to convert the list of data to a list of elements.
  const converListElement = (listElement) =>
    listElement?.map((additionalElement) =>
      convertToElement(additionalElement)
    );

  /* even if the Visualizers components have different fields this is not a problem:
  ex: titleAdditionalElements is available only for the TitleVisualizer, the other Visualizer will ignore this fields:
  It will be unpacked to "undefined" and the React component will ignore the param even if we pass it.
  */
  // eslint-disable-next-line prefer-const
  let {
    values,
    additionalElements,
    titleAdditionalElements,
    valueAdditionalElements,
    ...otherFields
  } = element;
  values = converListElement(values);
  additionalElements = converListElement(additionalElements);
  titleAdditionalElements = converListElement(titleAdditionalElements);
  valueAdditionalElements = converListElement(valueAdditionalElements);

  // this is a function used to convert the list of data to a list of elements.
  const converListElement = (listElement) =>
    listElement?.map((additionalElement) =>
      convertToElement(additionalElement)
    );

  /* even if the Visualizers components have different fields this is not a problem:
  ex: titleAdditionalElements is available only for the TitleVisualizer, the other Visualizer will ignore this fields:
  It will be unpacked to "undefined" and the React component will ignore the param even if we pass it.
  */
  let {
    values,
    additionalElements,
    titleAdditionalElements,
    valueAdditionalElements,
    // eslint-disable-next-line prefer-const
    ...otherFields
  } = element;
  values = converListElement(values);
  additionalElements = converListElement(additionalElements);
  titleAdditionalElements = converListElement(titleAdditionalElements);
  valueAdditionalElements = converListElement(valueAdditionalElements);

  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      return (
        <BooleanVisualizer
          additionalElements={additionalElements}
          {...otherFields}
        />
      );
    }
    case VisualizerComponentType.ICON: {
      return (
        <IconVisualizer
          additionalElements={additionalElements}
          {...otherFields}
        />
      );
    }
    case VisualizerComponentType.LIST: {
      return (
        <ListVisualizer
          values={values}
          additionalElements={additionalElements}
          {...otherFields}
        />
      );
    }
    case VisualizerComponentType.TITLE: {
      return (
        <TitleVisualizer
          titleAdditionalElements={titleAdditionalElements}
          valueAdditionalElements={valueAdditionalElements}
          {...otherFields}
        />
      );
    }
    default: {
      return (
        <BaseVisualizer
          additionalElements={additionalElements}
          {...otherFields}
        />
      );
    }
  }
}

export default function VisualizerReport({ job }) {
  console.debug("VisualizerReport rendered");
  console.debug("visualizer job");
  console.debug(job);

  // validate data
  const validatedData = mockedData.map((fieldElement) =>
    visualizerValidator(fieldElement)
  );
  validatedData.sort(
    (firstElement, secondElement) => firstElement.level - secondElement.level
  );

  console.debug("VisualizerReport - validatedData");
  console.debug(validatedData);

  // convert data to elements
  const elementData = validatedData.map((level) =>
    level.elements.map((element) => convertToElement(element))
  );

  console.debug("VisualizerReport - elementData");
  console.debug(elementData);

  // generate the levels/rows
  let levelElements = elementData.map((levelData, levelIndex) => {
    let levelSize = levelIndex * 2 + 3;
    if (levelSize > 6) {
      levelSize = 6;
    }
    if (levelData.filter((e) => e).length === 0) {
      return null;
    }
    return (
      <Fragment>
        <Row
          /* eslint-disable-next-line react/no-array-index-key */
          key={levelIndex}
          className={`justify-content-around align-items-center h${levelSize}`}
        >
          {levelData}
        </Row>
        {levelIndex + 1 !== validatedData.length && (
          <hr className="border-gray flex-grow-1" />
        )}
      </Fragment>
    );
  });

  console.debug("VisualizerReport - levelElements");
  console.debug(levelElements);

  if (levelElements.length === 0) {
    levelElements = (
      <p className="mb-0 text-center">
        No data to show in the UI. You can consult the results in the raw
        format.
      </p>
    );
  }

  return <ContentSection className="bg-body">{levelElements}</ContentSection>;
}

VisualizerReport.propTypes = {
  job: PropTypes.object.isRequired,
};
