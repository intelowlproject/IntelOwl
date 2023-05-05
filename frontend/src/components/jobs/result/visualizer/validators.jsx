import { VisualizerComponentType } from "./elements/const";

// common visualizer field components properties
function parseBool(value) {
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

function parseAlignment(alignment) {
  if (["start", "center", "end", "between", "around"].includes(alignment)) {
    return alignment;
  }
  return "around";
}

// parse list of Elements
function parseElementList(rawElementList) {
  return rawElementList?.map((additionalElementrawData) =>
    parseElementFields(additionalElementrawData)
  );
}

// parse a single element
function parseElementFields(rawElement) {
  // every component has the "type" field
  const validatedFields = { type: parseComponentType(rawElement.type) };
  // HList doesn't have this field, don't pass it even if it wouldn't be used
  if (rawElement.disable !== undefined) {
    validatedFields.disable = parseBool(rawElement.disable);
  }

  // validation for the elements
  switch (validatedFields.type) {
    case VisualizerComponentType.BOOL: {
      validatedFields.name = rawElement.name;
      validatedFields.value = parseBool(rawElement.value);
      validatedFields.icon = rawElement.icon;
      validatedFields.italic = parseBool(rawElement.italic);
      validatedFields.link = rawElement.link;
      validatedFields.className = rawElement.classname;
      validatedFields.activeColor = parseColor(rawElement.color, "danger");
      break;
    }
    case VisualizerComponentType.HLIST: {
      validatedFields.values = parseElementList(rawElement.values);
      validatedFields.alignment = parseAlignment(rawElement.alignment);
      break;
    }
    case VisualizerComponentType.VLIST: {
      validatedFields.name = parseElementFields(rawElement.name);
      validatedFields.values = parseElementList(rawElement.values);
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
      validatedFields.bold = parseBool(rawElement.bold);
      validatedFields.italic = parseBool(rawElement.italic);
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
