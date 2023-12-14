export const sanitizeObservable = (observable) =>
  observable.replaceAll("[", "").replaceAll("]", "").trim();
