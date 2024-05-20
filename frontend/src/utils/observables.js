import {
  DOMAIN_REGEX,
  IP_REGEX,
  URL_REGEX,
  HASH_REGEX,
  PHONE_REGEX,
} from "../constants/regexConst";
import {
  ObservableClassifications,
  FileExtensions,
  InvalidTLD,
} from "../constants/jobConst";

// IMPORTANT, order matters! phone must be checked after ip or the numbers will be taken as IP addesses
const observableType2RegExMap = {
  domain: DOMAIN_REGEX,
  ip: IP_REGEX,
  phone: PHONE_REGEX,
  url: URL_REGEX,
  hash: HASH_REGEX,
};

/* Remove [] inside the string, remove any no-word characters at the end of the string */
export function sanitizeObservable(observable) {
  return (
    observable
      .replaceAll("[", "")
      .replaceAll("]", "")
      .trim()
      .replace(/\W*$/, "")
      /* ignore + at the start of the string to support phone number:
    this could lead to a match problem in the loading observable feature */
      .replace(/^(?!\+)\W/, "")
  );
}

export function observableValidators(stringToValidate) {
  const sanitizedString = sanitizeObservable(stringToValidate);

  let stringClassification = "";
  Object.entries(observableType2RegExMap).forEach(([typeName, typeRegEx]) => {
    if (typeRegEx.test(sanitizedString)) {
      stringClassification = typeName;
      if (stringClassification === "phone")
        stringClassification = ObservableClassifications.GENERIC;
    }
  });

  // domain
  if (stringClassification === ObservableClassifications.DOMAIN) {
    const stringEnd = sanitizedString.split(".").pop();
    // remove file extentions and invalid TLD
    if (
      Object.values(FileExtensions)
        .concat(Object.values(InvalidTLD))
        .includes(stringEnd)
    )
      return null;
    // remove domain if stringEnd is a number
    if (!Number.isNaN(parseInt(stringEnd, 10))) return null;
  }

  // hash
  if (stringClassification === ObservableClassifications.HASH) {
    const hashTypesLength = {
      md5: 32,
      sha1: 40,
      sha256: 64,
      sha512: 128,
    };
    if (!Object.values(hashTypesLength).includes(sanitizedString.length))
      return null;
  }

  if (stringClassification)
    return {
      classification: stringClassification,
      observable: sanitizedString,
    };
  return null;
}

export function getObservableClassification(observable) {
  let classification = ObservableClassifications.GENERIC;
  const validationValue = observableValidators(observable);
  if (validationValue !== null) classification = validationValue.classification;
  return classification;
}
