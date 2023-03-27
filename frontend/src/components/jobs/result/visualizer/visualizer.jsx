import React from "react";
import PropTypes from "prop-types";
import { ContentSection } from "@certego/certego-ui";

import { visualizerValidator } from "./validators";

import { BooleanVisualizer } from "./elements/bool";
import { BaseVisualizer } from "./elements/base";
import { VerticalListVisualizer } from "./elements/verticalList";
import { TitleVisualizer } from "./elements/title";

import { VisualizerComponentType } from "./elements/const";
import { getIcon } from "./icons";

import { HorizontalListVisualizer } from "./elements/horizontalList";

const mockedData = [
  // disable level
  {
    level: 3,
    elements: {
      type: "horizontal_list",
      values: [
        {
          type: "title",
          title: "disable title",
          value: {},
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
          type: "base",
          name: "disable icon",
          icon: "",
          disable_if_empty: true,
        },
        {
          type: "vertical_list",
          name: "disable list",
          values: [],
          disable_if_empty: true,
        },
      ],
    },
  },
  // base level
  {
    level: 0,
    elements: {
      type: "horizontal_list",
      values: [
        {
          type: "title",
          title: {
            type: "base",
            value: "base title",
          },
          value: {
            type: "base",
            value: "base value",
            color: "dark",
          },
        },
        {
          type: "bool",
          name: "base bool",
          value: true,
        },
        {
          type: "base",
          value: "base base",
          color: "dark",
        },
        {
          type: "base",
          value: "icon label",
          icon: "quokka",
          link: "https://otx.alienvault.com/",
          color: "dark",
        },
        {
          type: "vertical_list",
          name: "base list (2)",
          values: [
            { type: "base", value: "VLIST - first elem" },
            { type: "base", value: "VLIST - second elem" },
          ],
        },
      ],
    },
  },
  // advanced (test all fields)
  {
    level: 1,
    elements: {
      type: "horizontal_list",
      values: [
        {
          type: "title",
          title: {
            type: "base",
            value: "advanced title title",
          },
          value: {
            type: "base",
            icon: "malware",
            color: "danger",
            value: "advanced title value",
          },
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "title",
          title: {
            type: "base",
            value: "advanced title2 title",
            icon: "otx",
            link: "https://otx.alienvault.com/",
          },
          value: {
            type: "base",
            value: "advanced title2 value",
            color: "dark",
          },
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "bool",
          name: "advanced bool",
          value: true,
          pill: false,
          link: "http://google.com",
          color: "success",
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "base",
          value: "advanced base",
          link: "http://google.com",
          color: "warning",
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "base",
          value: "advanced icon",
          icon: "google",
          link: "http://google.com",
          color: "success",
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "vertical_list",
          name: "advanced list (1)",
          icon: "otx",
          color: "primary",
          link: "https://otx.alienvault.com/",
          values: [{ type: "base", value: "advanced list - 1st item" }],
          open: true,
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "vertical_list",
          name: "advanced list2 (3)",
          link: "",
          values: [
            {
              type: "horizontal_list",
              values: [
                { type: "base", value: "first" },
                {
                  type: "base",
                  icon: "otx",
                  link: "https://otx.alienvault.com/",
                },
                {
                  type: "base",
                  icon: "virusTotal",
                  link: "https://www.virustotal.com/gui/home/search",
                },
                { type: "base", icon: "hybridAnalysis" },
              ],
            },
            {
              type: "horizontal_list",
              values: [{ type: "base", value: "second" }],
            },
            {
              type: "horizontal_list",
              values: [
                { type: "base", value: "third" },
                { type: "base", icon: "otx" },
                { type: "base", icon: "hybridAnalysis" },
              ],
            },
          ],
          open: true,
          hide_if_empty: true,
          disable_if_empty: true,
        },
      ],
    },
  },
  // hide level
  {
    level: 2,
    elements: {
      type: "horizontal_list",
      values: [
        {
          type: "title",
          title: {
            type: "base",
            value: "",
          },
          value: {},
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
          type: "base",
          name: "hide icon",
          value: "",
          icon: "",
          hide_if_empty: true,
          disable_if_empty: true,
        },
        {
          type: "vertical_list",
          name: "hide list",
          values: [],
          hide_if_empty: true,
          disable_if_empty: true,
        },
      ],
    },
  },
];

/**
 * Convert the validated data into a VisualizerElement.
 * This is a recursive function: It's called by the component to convert the inner components.
 *
 * @param {object} element data used to generate the component
 * @returns {React.Component} component to visualize
 */
export function convertToElement(element) {
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      return (
        <BooleanVisualizer
          name={element.name}
          value={element.value}
          pill={element.pill}
          link={element.link}
          className={element.className}
          activeColor={element.activeColor}
          hideIfEmpty={element.hideIfEmpty}
          disableIfEmpty={element.disableIfEmpty}
        />
      );
    }
    case VisualizerComponentType.HLIST: {
      return (
        <HorizontalListVisualizer
          values={element.values?.map((additionalElement) =>
            convertToElement(additionalElement)
          )}
        />
      );
    }
    case VisualizerComponentType.VLIST: {
      return (
        <VerticalListVisualizer
          name={element.name}
          values={element.values?.map((additionalElement) =>
            convertToElement(additionalElement)
          )}
          icon={getIcon(element.icon)}
          color={element.color}
          link={element.link}
          className={element.className}
          startOpen={element.startOpen}
          hideIfEmpty={element.hideIfEmpty}
          disableIfEmpty={element.disableIfEmpty}
        />
      );
    }
    case VisualizerComponentType.TITLE: {
      return (
        <TitleVisualizer
          title={convertToElement(element.title)}
          value={convertToElement(element.value)}
          hideIfEmpty={element.hideIfEmpty}
          disableIfEmpty={element.disableIfEmpty}
        />
      );
    }
    default: {
      return (
        <BaseVisualizer
          value={element.value}
          icon={getIcon(element.icon)}
          color={element.color}
          link={element.link}
          className={element.className}
          hideIfEmpty={element.hideIfEmpty}
          disableIfEmpty={element.disableIfEmpty}
        />
      );
    }
  }
}

export default function VisualizerReport({ visualizerReport }) {
  console.debug("VisualizerReport - visualizerReport");
  console.debug(visualizerReport);

  console.debug("mockedData");
  console.debug(mockedData);
  // validate data
  const validatedData = visualizerReport.report.map((fieldElement) =>
    // const validatedData = mockedData.map((fieldElement) =>
    visualizerValidator(fieldElement)
  );
  validatedData.sort(
    (firstElement, secondElement) => firstElement.level - secondElement.level
  );

  console.debug("VisualizerReport - validatedData");
  console.debug(validatedData);

  // convert data to elements
  const elementData = validatedData.map((level) =>
    convertToElement(level.elements)
  );

  console.debug("VisualizerReport - elementData");
  console.debug(elementData);

  // generate the levels/rows
  let levelElements = elementData.map((levelData, levelIndex) => {
    let levelSize = levelIndex * 2 + 3;
    if (levelSize > 6) {
      levelSize = 6;
    }
    return (
      <div className={`h${levelSize}`}>
        {levelData}
        {levelIndex + 1 !== validatedData.length && (
          <hr className="border-gray flex-grow-1" />
        )}
      </div>
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
  visualizerReport: PropTypes.object.isRequired,
};
