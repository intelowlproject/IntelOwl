export const fileDownload = (blob, filename) => {
  // create URL blob and a hidden <a> tag to serve file for download
  const fileLink = document.createElement("a");
  fileLink.href = window.URL.createObjectURL(blob);
  fileLink.rel = "noopener,noreferrer";
  fileLink.download = `${filename}`;
  // triggers the click event
  fileLink.click();
  console.debug("clicked");
};

export const humanReadbleSize = (byteNumber) => {
  if (byteNumber === 0) {
    return "0.00 B";
  }
  const number = Math.floor(Math.log(byteNumber) / Math.log(1024));
  return `${(byteNumber / 1024 ** number).toFixed(2)} ${" KMGTP".charAt(
    number,
  )}B`;
};
