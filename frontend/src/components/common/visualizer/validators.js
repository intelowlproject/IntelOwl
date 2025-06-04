import { FileMimeTypes } from "../../../constants/jobConst";
import { VisualizerComponentType } from "./elements/const";

function parseLevelSize(value) {
  if (["1", "2", "3", "4", "5", "6"].includes(value)) {
    return `h${value}`;
  }
  return "h6";
}

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

function parseElementSize(value) {
  if (
    [
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "10",
      "11",
      "12",
      "auto",
    ].includes(value)
  ) {
    return `col-${value}`;
  }
  return "col-auto";
}

function parseElementWidth(value) {
  if ([50, 100, 150, 200, 250, 300].includes(value)) {
    return value;
  }
  return 300;
}

function parseComponentType(value) {
  if (Object.values(VisualizerComponentType).includes(value)) {
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

function parseString(value) {
  const stringValue = value;
  // avoid to convert 0 to ""
  if (value === null || value === undefined) return "";
  // avoid [object Object] for the dict
  if (typeof value === "object" && !Array.isArray(value))
    return JSON.stringify(value);
  return String(stringValue);
}

function parseMimetype(value) {
  if (Object.values(FileMimeTypes).includes(value)) {
    return value;
  }
  return FileMimeTypes.OCTET;
}

// parse list of Elements
function parseElementList(rawElementList) {
  if (!Array.isArray(rawElementList)) {
    return [];
  }
  return rawElementList?.map((additionalElementrawData) =>
    parseElementFields(additionalElementrawData),
  );
}

// parse list of dict with this format {key: Element}
function parseElementListOfDict(rawElementList) {
  return rawElementList?.map((additionalElementrawData) => {
    const obj = {};
    Object.entries(additionalElementrawData).forEach(([key, value]) => {
      obj[key] = parseElementFields(value);
    });
    return obj;
  });
}

// parse list of Column Elements
function parseColumnElementList(rawElementList) {
  return {
    name: parseString(rawElementList.name),
    maxWidth: parseElementWidth(rawElementList.max_width),
    description: parseString(rawElementList.description),
    disableFilters: parseBool(rawElementList.disable_filters),
    disableSortBy: parseBool(rawElementList.disable_sort_by),
  };
}

// parse a single element
function parseElementFields(rawElement) {
  // HList and Title don't have disable field, they will not be used
  const validatedFields = {
    type: parseComponentType(rawElement.type),
    disable: parseBool(rawElement.disable),
    size: parseElementSize(rawElement.size),
    alignment: parseAlignment(rawElement.alignment),
  };

  // validation for the elements
  switch (validatedFields.type) {
    case VisualizerComponentType.DOWNLOAD: {
      validatedFields.value = parseString(rawElement.value);
      validatedFields.mimetype = parseMimetype(rawElement.mimetype);
      validatedFields.payload = parseString(rawElement.payload);
      validatedFields.copyText = parseString(
        rawElement.copy_text || rawElement.value,
      );
      validatedFields.description = parseString(rawElement.description);
      validatedFields.addMetadataInDescription = parseBool(
        rawElement.add_metadata_in_description,
      );
      validatedFields.link = parseString(rawElement.link);
      break;
    }
    case VisualizerComponentType.BOOL: {
      validatedFields.value = parseString(rawElement.value);
      validatedFields.icon = parseString(rawElement.icon);
      validatedFields.activeColor = parseColor(rawElement.color, "danger");
      validatedFields.italic = parseBool(rawElement.italic);
      validatedFields.link = parseString(rawElement.link);
      validatedFields.copyText = parseString(
        rawElement.copy_text || rawElement.value,
      );
      validatedFields.description = parseString(rawElement.description);
      break;
    }
    case VisualizerComponentType.HLIST: {
      validatedFields.values = parseElementList(rawElement.values || []);
      break;
    }
    case VisualizerComponentType.VLIST: {
      if (rawElement.name !== null)
        validatedFields.name = parseElementFields(rawElement.name);
      else validatedFields.name = rawElement.name;
      validatedFields.values = parseElementList(rawElement.values || []);
      validatedFields.startOpen = parseBool(rawElement.start_open);
      break;
    }
    case VisualizerComponentType.TITLE: {
      validatedFields.title = parseElementFields(rawElement.title);
      validatedFields.value = parseElementFields(rawElement.value);
      break;
    }
    case VisualizerComponentType.TABLE: {
      validatedFields.data = parseElementListOfDict(rawElement.data || []);
      validatedFields.columns = Array.isArray(rawElement.columns)
        ? rawElement.columns.map((column) => parseColumnElementList(column))
        : [];
      validatedFields.pageSize = rawElement.page_size;
      validatedFields.sortById = parseString(rawElement.sort_by_id);
      validatedFields.sortByDesc = parseBool(rawElement.sort_by_desc);
      break;
    }
    // base case
    default: {
      validatedFields.value = parseString(rawElement.value);
      validatedFields.icon = parseString(rawElement.icon);
      validatedFields.color = `bg-${parseColor(rawElement.color)}`;
      validatedFields.italic = parseBool(rawElement.italic);
      validatedFields.link = parseString(rawElement.link);
      validatedFields.bold = parseBool(rawElement.bold);
      validatedFields.copyText = parseString(
        rawElement.copy_text || rawElement.value,
      );
      validatedFields.description = parseString(rawElement.description);
      break;
    }
  }
  return validatedFields;
}

// validate the visualizer rows
export function validateLevel(levelRawData) {
  const levelPosition = parseFloat(levelRawData.level_position);
  const levelSize = parseLevelSize(levelRawData.level_size);
  const elements = parseElementFields(levelRawData.elements);
  return { levelPosition, levelSize, elements };
}
