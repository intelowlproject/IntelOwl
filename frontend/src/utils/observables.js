import {
  DOMAIN_REGEX,
  IP_REGEX,
  URL_REGEX,
  HASH_REGEX,
} from "../constants/regexConst";
import { ObservableClassifications } from "../constants/jobConst";

export function sanitizeObservable(observable) {
  return observable.replaceAll("[", "").replaceAll("]", "").trim();
}

export function getObservableClassification(observable) {
  const observableType2RegExMap = {
    domain: DOMAIN_REGEX,
    ip: IP_REGEX,
    url: URL_REGEX,
    hash: HASH_REGEX,
  };

  let classification = ObservableClassifications.GENERIC;
  Object.entries(observableType2RegExMap).forEach(([typeName, typeRegEx]) => {
    if (typeRegEx.test(sanitizeObservable(observable))) {
      classification = typeName;
    }
  });

  return classification;
}
