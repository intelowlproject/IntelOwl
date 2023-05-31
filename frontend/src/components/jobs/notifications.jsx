import { PUBLIC_URL } from "../../constants/environment";

// This function is used to generate a notification when a Job is terminated
export function generateJobNotification(observableName, jobId) {
  console.debug(
    `send notification for observable: ${observableName}(${jobId})`
  );
  Notification.requestPermission().then((result) => {
    if (result === "granted") {
      // notification audio
      new Audio(`${PUBLIC_URL}/notification.mp3`)
        .play()
        .then()
        .catch((e) => console.error(e));

      // notification icon
      setNotificationFavicon(true);

      const notification = new Notification("IntelOwl analysis terminated!", {
        body: `Observable: ${observableName} (job ${jobId}) reported.\n Click here to view the result!`,
        icon: `${PUBLIC_URL}/logo-blue.png`,
      });

      // close the notification after 5 seconds
      setTimeout(() => {
        notification.close();
      }, 10 * 1000);

      // navigate to the Job report page when clicked
      notification.addEventListener("click", () => {
        window.open(`/jobs/${jobId}`, '_blank,noopener,noreferrer"');
      });
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        "Without the permission for the notifications IntelOwl cannot report when Jobs terminated"
      );
    }
  });
}

// This function allow to toggle favicon and notification favicon
export function setNotificationFavicon(isNotification) {
  const actualIcon = document.head.querySelector('link[rel="shortcut icon"]');
  actualIcon.href = isNotification
    ? `${PUBLIC_URL}/icons/favicon-notification.ico`
    : `${PUBLIC_URL}/icons/favicon.ico`;
}
