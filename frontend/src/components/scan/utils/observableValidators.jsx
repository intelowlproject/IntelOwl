import {
  DOMAIN_REGEX,
  IP_REGEX,
  HASH_REGEX,
  URL_REGEX,
} from "../../../constants/regexConst";
import {
  ObservableClassifications,
  FileExtensions,
  InvalidTLD,
} from "../../../constants/jobConst";

/* Remove [] inside the string, remove any no-word characters at the end of the string */
export const sanitizeObservable = (observable) =>
  observable
    .replaceAll("[", "")
    .replaceAll("]", "")
    .trim()
    .replace(/\W*$/, "")
    .replace(/^\W/, "");

const observableType2RegExMap = {
  domain: DOMAIN_REGEX,
  ip: IP_REGEX,
  url: URL_REGEX,
  hash: HASH_REGEX,
};

export function observableValidators(stringToValidate) {
  const sanitizedString = sanitizeObservable(stringToValidate);

  let stringClassification = "";
  Object.entries(observableType2RegExMap).forEach(([typeName, typeRegEx]) => {
    if (typeRegEx.test(sanitizedString)) {
      stringClassification = typeName;
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
