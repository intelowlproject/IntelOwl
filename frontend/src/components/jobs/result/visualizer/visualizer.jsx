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
 * @returns {Object} component to visualize
 */
export function convertToElement(element) {
  let visualizerElement;
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      visualizerElement = (
        <BooleanVisualizer
          size={element.size}
          name={element.name}
          value={element.value}
          link={element.link}
          className={element.className}
          activeColor={element.activeColor}
          disable={element.disable}
          icon={getIcon(element.icon)}
          italic={element.italic}
        />
      );
      break;
    }
    case VisualizerComponentType.HLIST: {
      visualizerElement = (
        <HorizontalListVisualizer
          values={element.values.map((additionalElement) =>
            convertToElement(additionalElement)
          )}
          alignment={element.alignment}
        />
      );
      break;
    }
    case VisualizerComponentType.VLIST: {
      visualizerElement = (
        <VerticalListVisualizer
          size={element.size}
          name={convertToElement(element.name)}
          values={element.values.map((additionalElement) =>
            convertToElement(additionalElement)
          )}
          className={element.className}
          startOpen={element.startOpen}
          disable={element.disable}
        />
      );
      break;
    }
    case VisualizerComponentType.TITLE: {
      visualizerElement = (
        <TitleVisualizer
          size={element.size}
          title={convertToElement(element.title)}
          value={convertToElement(element.value)}
        />
      );
      break;
    }
    default: {
      visualizerElement = (
        <BaseVisualizer
          size={element.size}
          value={element.value}
          icon={getIcon(element.icon)}
          color={element.color}
          link={element.link}
          bold={element.bold}
          italic={element.italic}
          className={element.className}
          disable={element.disable}
        />
      );
      break;
    }
  }
  return visualizerElement;
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
          <hr className="border-gray flex-grow-1 my-2" />
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
