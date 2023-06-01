import React from "react";
import PropTypes from "prop-types";
import { ContentSection, ErrorAlert } from "@certego/certego-ui";

import { validateLevel } from "./validators";

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
function convertToElement(element) {
  let visualizerElement;
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      visualizerElement = (
        <BooleanVisualizer
          size={element.size}
          value={element.value}
          link={element.link}
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
          alignment={element.alignment}
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
          alignment={element.alignment}
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
          alignment={element.alignment}
          value={element.value}
          icon={getIcon(element.icon)}
          color={element.color}
          link={element.link}
          bold={element.bold}
          italic={element.italic}
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

  // in case there are some errors, show them
  if (visualizerReport.errors.length) {
    return (
      <ErrorAlert
        error={{
          response: {
            statusText: "An error occurred during the rendering",
          },
          parsedMsg: visualizerReport.errors,
        }}
      />
    );
  }

  // validate data
  const validatedLevels = visualizerReport.report.map((levelElement) =>
    validateLevel(levelElement)
  );
  validatedLevels.sort(
    (firstLevel, secondLevel) => firstLevel.level - secondLevel.level
  );

  console.debug("VisualizerReport - validatedLevels");
  console.debug(validatedLevels);

  // convert data to elements
  const levels = validatedLevels.map((level) =>
    convertToElement(level.elements)
  );

  console.debug("VisualizerReport - levels");
  console.debug(levels);

  // generate the levels/rows
  let levelElements = levels.map((levelData, levelIndex) => {
    let levelSize = levelIndex * 2 + 3;
    if (levelSize > 6) {
      levelSize = 6;
    }
    return (
      <div className={`h${levelSize}`}>
        {levelData}
        {levelIndex + 1 !== levels.length && (
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
