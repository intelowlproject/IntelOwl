import { VisualizerComponentType } from "./elements/const";

// common visualizer field components properties
function parseBool(value, defaultValue = false) {
  if (value === undefined) {
    return defaultValue;
  }
  if (typeof value === "object") {
    if (Array.isArray(value)) {
      return value.length !== 0;
    }
    return Object.keys(value).length !== 0;
  }
  return !!value;
}

function parseComponentType(value) {
  if (
    [
      VisualizerComponentType.BASE,
      VisualizerComponentType.TITLE,
      VisualizerComponentType.BOOL,
      VisualizerComponentType.ICON,
      VisualizerComponentType.LIST,
    ].includes(value)
  ) {
    return value;
  }
  // default type
  return VisualizerComponentType.BASE;
}

function parseColor(color, defaultColor) {
  if (
    [
      "primary",
      "secondary",
      "tertiary",
      "success",
      "danger",
      "warning",
      "info",
      "dark",
      "white",
    ].includes(color)
  ) {
    return color;
  }
  return defaultColor;
}

// parse list of Elements
function parseElementList(rawElementList) {
  return rawElementList?.map((additionalElementrawData) =>
    parseElementFields(additionalElementrawData)
  );
}

// parse a single element
function parseElementFields(rawElement) {
  const type = parseComponentType(rawElement.type);
  const hideIfEmpty = parseBool(rawElement.hide_if_empty, false);
  const disableIfEmpty = parseBool(rawElement.disable_if_empty, true);

  // common fields
  const validatedFields = { type, hideIfEmpty, disableIfEmpty };

  // validation for the elements
  switch (type) {
    case VisualizerComponentType.BOOL: {
      validatedFields.name = rawElement.name;
      validatedFields.value = parseBool(rawElement.value);
      validatedFields.pill = parseBool(rawElement.pill, true);
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.activeColor = parseColor(rawElement.color, "danger");
      validatedFields.additionalElements = parseElementList(
        rawElement?.elements
      );
      break;
    }
    case VisualizerComponentType.ICON: {
      validatedFields.name = rawElement.name;
      validatedFields.icon = rawElement.value;
      validatedFields.color = `bg-${parseColor(rawElement.color, "dark")}`;
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.additionalElements = parseElementList(
        rawElement?.elements
      );
      break;
    }
    case VisualizerComponentType.LIST: {
      validatedFields.name = rawElement.name;
      validatedFields.values = rawElement.values?.map((valueElement) =>
        parseElementFields(valueElement)
      );
      validatedFields.color = parseColor(rawElement.color);
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.additionalElements = parseElementList(
        rawElement?.elements
      );
      validatedFields.startOpen = parseBool(rawElement.open);
      break;
    }
    case VisualizerComponentType.TITLE: {
      validatedFields.title = rawElement.title;
      validatedFields.value = rawElement.value;
      validatedFields.titleColor = `bg-${parseColor(rawElement.title_color)}`;
      validatedFields.titleLink = rawElement.title_link;
      validatedFields.titleClassName = rawElement.title_classname;
      validatedFields.titleAdditionalElements = parseElementList(
        rawElement?.title_elements
      );
      validatedFields.valueColor = `bg-${parseColor(
        rawElement.value_color,
        "dark"
      )}`;
      validatedFields.valueLink = rawElement.value_link;
      validatedFields.valueClassName = rawElement.value_classname;
      validatedFields.valueAdditionalElements = parseElementList(
        rawElement?.value_elements
      );
      break;
    }
    // base case
    default: {
      validatedFields.value = rawElement.value;
      validatedFields.color = `bg-${parseColor(rawElement.color)}`;
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.additionalElements = parseElementList(
        rawElement?.elements
      );
      break;
    }
  }
  return validatedFields;
}

// validate the visualizer rows
export function visualizerValidator(levelRawData) {
  const level = parseFloat(levelRawData.level);
  const elements = parseElementList(levelRawData.elements);
  return { level, elements };
}
