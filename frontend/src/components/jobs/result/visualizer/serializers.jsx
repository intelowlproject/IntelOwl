import React from "react";
import { iconMapping } from "./mappings";

export function StringVisualizerSerializer(additionalConfig = {}) {
  /* expected data format:
    {
        name: "field1",
        value: "test",
        additional_config: { value_color: "danger", value_icon: "danger" },
    }
    */
  let { title_color: titleColor, value_color: valueColor } = additionalConfig;
  const {
    title_link: titleLink,
    title_icon: titleIcon,
    value_link: valueLink,
    value_icon: valueIcon,
  } = additionalConfig;
  // convert icon field to icon element
  titleColor = `text-${titleColor}`;
  valueColor = `text-${valueColor}`;
  const titleAdditionalElement = iconMapping[titleIcon];
  const valueAdditionalElement = iconMapping[valueIcon];
  return {
    titleColor,
    titleLink,
    titleAdditionalElement,
    valueColor,
    valueLink,
    valueAdditionalElement,
  };
}

export function BooleanVisualizerSerializer(additionalConfig = {}) {
  /* expected data format:
    { 
        name: "field1",
        value: true,
        additional_config: {pill: false, icon: "urlhaus", active_color: "success"}
    }
    */
  const { active_color: activeColor, pill, icon } = additionalConfig;
  const additionalElement = iconMapping[icon];
  return {
    activeColor,
    pill,
    additionalElement,
  };
}

export function ListVisualizerSerializer(fieldValue, additionalConfig = {}) {
  /* expected data format:
    { 
        
    }
    */
  // sanitize values
  const convertedValue = fieldValue.map((listElement) => {
    const parsedElement = {
      elementValue: listElement.value,
      elementColor: `text-${listElement.color}`,
      elementLink: listElement.link,
    };
    let elementAdditionalElement = null;
    if (
      listElement.additional_config &&
      Array.isArray(listElement.additional_config)
    ) {
      elementAdditionalElement = (
        <div className="d-flex flex-horizontal">
          {listElement.additional_config.map((elementAC) => (
            <a href={elementAC.link} target="_blank" rel="noreferrer">
              {iconMapping[elementAC.icon]}
            </a>
          ))}
        </div>
      );
    }
    parsedElement.elementAdditionalElement = elementAdditionalElement;
    return parsedElement;
  });
  // additional config for the title
  let { title_color: titleColor } = additionalConfig;
  const { title_link: titleLink, title_icon: titleIcon } = additionalConfig;
  // convert icon field to icon element
  titleColor = `text-${titleColor}`;
  const titleAdditionalElement = iconMapping[titleIcon];
  return {
    titleColor,
    titleLink,
    titleAdditionalElement,
    convertedValue,
  };
}
