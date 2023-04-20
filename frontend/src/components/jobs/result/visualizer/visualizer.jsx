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
 * @param {boolean} isChild set to true in case an element is use into another (Ex: base is used in Title title and Title value)
 * @returns {Object} component to visualize
 */
export function convertToElement(element, isChild = false) {
  let visualizerElement;
  switch (element.type) {
    case VisualizerComponentType.BOOL: {
      visualizerElement = (
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
      break;
    }
    case VisualizerComponentType.HLIST: {
      /* This is a special case and it's the opposit of the others:
      We WANT to force the spaces between chidren (because are different componets)
      and we DON'T WANT to add the space for this specific component (because is a wrapper) 
      */
      // eslint-disable-next-line no-param-reassign
      isChild = true;
      visualizerElement = (
        <HorizontalListVisualizer
          values={element.values?.map((additionalElement) =>
            convertToElement(additionalElement)
          )}
        />
      );
      break;
    }
    case VisualizerComponentType.VLIST: {
      visualizerElement = (
        <VerticalListVisualizer
          name={element.name}
          values={element.values?.map((additionalElement) =>
            convertToElement(additionalElement, true)
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
      break;
    }
    case VisualizerComponentType.TITLE: {
      visualizerElement = (
        <TitleVisualizer
          title={convertToElement(element.title, true)}
          value={convertToElement(element.value, true)}
          hideIfEmpty={element.hideIfEmpty}
          disableIfEmpty={element.disableIfEmpty}
        />
      );
      break;
    }
    default: {
      visualizerElement = (
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
      break;
    }
  }
  return (
    // child component are wrapped into other component: they don't have mb, we don't want to create space inside a component.
    <div className={`col-auto ${isChild ? "" : "mb-1"}`}>
      {visualizerElement}
    </div>
  );
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
