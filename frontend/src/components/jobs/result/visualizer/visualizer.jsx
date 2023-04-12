// @ts-nocheck
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

/**
 * Convert the validated data into a VisualizerElement.
 * This is a recursive function: It's called by the component to convert the inner components.
 *
 * @param {object} element data used to generate the component
 * @param {bool} standAloneBase flag used to set the capitalize in the base components only in case is not used for VList or Title elements
 * @returns {React.Component} component to visualize
 */
function convertToElement(element, standAloneBase = true) {
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
            convertToElement(additionalElement, false)
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
          value={convertToElement(element.value, false)}
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
          className={`${standAloneBase ? "text-capitalize" : ""} ${
            element.className
          }`}
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

  // validate data
  const validatedData = visualizerReport.report.map((fieldElement) =>
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
