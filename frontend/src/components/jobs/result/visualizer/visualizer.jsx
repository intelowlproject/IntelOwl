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
 * @param {bool} isChild flag used in Title and VList to create a smaller children components.
 * @returns {Object} component to visualize
 */
function convertToElement(element, idElement, isChild = false) {
  let visualizerElement;
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      visualizerElement = (
        <BooleanVisualizer
          key={idElement}
          id={idElement}
          size={element.size}
          value={element.value}
          link={element.link}
          activeColor={element.activeColor}
          disable={element.disable}
          icon={getIcon(element.icon)}
          italic={element.italic}
          copyText={element.copyText}
          description={element.description}
        />
      );
      break;
    }
    case VisualizerComponentType.HLIST: {
      visualizerElement = (
        <HorizontalListVisualizer
          key={idElement}
          id={idElement}
          values={element.values.map((additionalElement, index) =>
            /* simply pass the isChild:
          in case of this is the first element (level) we don't need to render the components as children (defaul false is ok).
          in case this is a child (part of vlist) we pass isChild=true to its children
          */
            convertToElement(
              additionalElement,
              `${idElement}-${index}`,
              isChild,
            ),
          )}
          alignment={element.alignment}
        />
      );
      break;
    }
    case VisualizerComponentType.VLIST: {
      visualizerElement = (
        <VerticalListVisualizer
          key={idElement}
          id={idElement}
          size={element.size}
          name={convertToElement(element.name, `${idElement}-vlist`)}
          values={element.values.map((additionalElement, index) =>
            convertToElement(
              additionalElement,
              `${idElement}-item${index}`,
              true,
            ),
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
          key={idElement}
          id={idElement}
          size={element.size}
          alignment={element.alignment}
          title={convertToElement(element.title, `${idElement}-title`)}
          value={convertToElement(element.value, `${idElement}-value`, true)}
        />
      );
      break;
    }
    default: {
      visualizerElement = (
        <BaseVisualizer
          key={idElement}
          id={idElement}
          size={element.size}
          alignment={element.alignment}
          value={element.value}
          icon={getIcon(element.icon)}
          color={element.color}
          link={element.link}
          bold={element.bold}
          italic={element.italic}
          disable={element.disable}
          copyText={element.copyText}
          isChild={isChild}
          description={element.description}
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
    validateLevel(levelElement),
  );
  validatedLevels.sort(
    (currentLevel, nextLevel) =>
      currentLevel.levelPosition - nextLevel.levelPosition,
  );

  console.debug("VisualizerReport - validatedLevels");
  console.debug(validatedLevels);

  // convert data to elements
  const levels = validatedLevels.map((level) => ({
    levelSize: level.levelSize,
    elements: convertToElement(
      level.elements,
      `page${visualizerReport.id}-level${level.levelPosition}`,
    ),
  }));

  console.debug("VisualizerReport - levels");
  console.debug(levels);

  // generate the levels/rows
  let levelElements = levels.map((levelData, levelIndex) => (
    <div className={levelData.levelSize}>
      {levelData.elements}
      {levelIndex + 1 !== levels.length && (
        <hr className="border-gray flex-grow-1 my-2" />
      )}
    </div>
  ));

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
