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
      VisualizerComponentType.VLIST,
      VisualizerComponentType.HLIST,
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
      break;
    }
    case VisualizerComponentType.HLIST: {
      validatedFields.values = parseElementList(rawElement.values);
      break;
    }
    case VisualizerComponentType.VLIST: {
      validatedFields.name = rawElement.name;
      validatedFields.values = parseElementList(rawElement.values);
      validatedFields.icon = rawElement.icon;
      validatedFields.color = parseColor(rawElement.color);
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.startOpen = parseBool(rawElement.open);
      break;
    }
    case VisualizerComponentType.TITLE: {
      validatedFields.title = parseElementFields(rawElement.title);
      validatedFields.value = parseElementFields(rawElement.value);
      break;
    }
    // base case
    default: {
      validatedFields.value = rawElement.value;
      validatedFields.icon = rawElement.icon;
      validatedFields.color = `bg-${parseColor(rawElement.color)}`;
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      break;
    }
  }
  return validatedFields;
}

// validate the visualizer rows
export function visualizerValidator(levelRawData) {
  const level = parseFloat(levelRawData.level);
  const elements = parseElementFields(levelRawData.elements);
  return { level, elements };
}
