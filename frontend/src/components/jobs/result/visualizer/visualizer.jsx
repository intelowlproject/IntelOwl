import React, { Fragment } from "react";
import PropTypes from "prop-types";
import { ContentSection } from "@certego/certego-ui";
import { Row } from "reactstrap";

import { visualizerValidator } from "./validators";

import { BooleanVisualizerField } from "./elements/bool";
import { BaseVisualizerField } from "./elements/base";
import { ListVisualizerField } from "./elements/list";
import { IconVisualizerField } from "./elements/icon";
import { TitleVisualizerField } from "./elements/title";

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

function convertToElement(element) {
  // switch(element.type) {
  //   case VisualizerComponentType.BOOL: {
  //     return <BooleanVisualizerField
  //       name={element.name}
  //       value={element.value}
  //       pill={element.pill}
  //       link={element.link}
  //       className={element.className}
  //       activeColor={element.activeColor}
  //       additionalElements={element.additionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       hideIfEmpty={element.hideIfEmpty}
  //       disableIfEmpty={element.disableIfEmpty}
  //     />
  //   }
  //   case VisualizerComponentType.ICON: {
  //     return <IconVisualizerField
  //       name={element.name}
  //       icon={element.icon}
  //       color={element.color}
  //       link={element.link}
  //       className={element.className}
  //       additionalElements={element.additionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       hideIfEmpty={element.hideIfEmpty}
  //       disableIfEmpty={element.disableIfEmpty}
  //     />
  //   }
  //   case VisualizerComponentType.LIST: {
  //     return <ListVisualizerField
  //       name={element.name}
  //       values={element.values.map(additionalElement => convertToElement(additionalElement))}
  //       color={element.color}
  //       link={element.link}
  //       className={element.className}
  //       additionalElements={element.additionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       startOpen={element.startOpen}
  //       hideIfEmpty={element.hideIfEmpty}
  //       disableIfEmpty={element.disableIfEmpty}
  //     />
  //   }
  //   case VisualizerComponentType.TITLE: {
  //     return <TitleVisualizerField
  //       title={element.title}
  //       value={element.value}
  //       titleColor={element.titleColor}
  //       titleLink={element.titleLink}
  //       titleClassName={element.titleClassName}
  //       titleAdditionalElements={element.titleAdditionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       valueColor={element.valueColor}
  //       valueLink={element.valueLink}
  //       valueClassName={element.valueClassName}
  //       valueAdditionalElements={element.valueAdditionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       hideIfEmpty={element.hideIfEmpty}
  //       disableIfEmpty={element.disableIfEmpty}
  //     />
  //   }
  //   default: {
  //     return <BaseVisualizerField
  //       value={element.value}
  //       color={element.color}
  //       link={element.link}
  //       className={element.className}
  //       additionalElements={element.additionalElements?.map(additionalElement => convertToElement(additionalElement))}
  //       hideIfEmpty={element.hideIfEmpty}
  //       disableIfEmpty={element.disableIfEmpty}
  //     />
  //   }
  // }
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      // eslint-disable-next-line prefer-const
      let { additionalElements, ...otherFields } = element;
      additionalElements = additionalElements?.map((additionalElement) =>
        convertToElement(additionalElement)
      );
      return (
        <BooleanVisualizerField
          {...otherFields}
          additionalElements={additionalElements}
        />
      );
    }
    case VisualizerComponentType.ICON: {
      // eslint-disable-next-line prefer-const
      let { additionalElements, ...otherFields } = element;
      additionalElements = additionalElements?.map((additionalElement) =>
        convertToElement(additionalElement)
      );
      return (
        <IconVisualizerField
          {...otherFields}
          additionalElements={additionalElements}
        />
      );
    }
    case VisualizerComponentType.LIST: {
      // eslint-disable-next-line prefer-const
      let { values, additionalElements, ...otherFields } = element;
      values = element.values.map((additionalElement) =>
        convertToElement(additionalElement)
      );
      additionalElements = additionalElements?.map((additionalElement) =>
        convertToElement(additionalElement)
      );
      return (
        <ListVisualizerField
          {...otherFields}
          values={values}
          additionalElements={additionalElements}
        />
      );
    }
    case VisualizerComponentType.TITLE: {
      // eslint-disable-next-line prefer-const
      let { titleAdditionalElements, valueAdditionalElements, ...otherFields } =
        element;
      titleAdditionalElements = element.titleAdditionalElements?.map(
        (additionalElement) => convertToElement(additionalElement)
      );
      valueAdditionalElements = valueAdditionalElements?.map(
        (additionalElement) => convertToElement(additionalElement)
      );
      return (
        <TitleVisualizerField
          {...otherFields}
          titleAdditionalElements={titleAdditionalElements}
          valueAdditionalElements={valueAdditionalElements}
        />
      );
    }
    default: {
      // eslint-disable-next-line prefer-const
      let { additionalElements, ...otherFields } = element;
      additionalElements = element.additionalElements?.map(
        (additionalElement) => convertToElement(additionalElement)
      );
      return (
        <BaseVisualizerField
          {...otherFields}
          additionalElements={additionalElements}
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
        {/* eslint-disable-next-line react/no-array-index-key */}
        <Row
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
