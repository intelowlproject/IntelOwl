import React from "react";
import { Badge, UncontrolledPopover } from "reactstrap";
import { IoMdNotifications } from "react-icons/io";

import { IconButton, Tabs, useAxiosComponentLoader } from "@certego/certego-ui";

import { NOTIFICATION_BASE_URI } from "../../../constants/api";
import NotificationsList from "./NotificationsList";

export default function NotificationPopoverButton() {
  // API
  const [unreadNotifs, Loader1, refetch1] = useAxiosComponentLoader(
    {
      url: NOTIFICATION_BASE_URI,
      params: { page_size: 4, read: false },
    },
    (respData) => respData?.results
  );

  const [readNotifs, Loader2, refetch2] = useAxiosComponentLoader(
    {
      url: NOTIFICATION_BASE_URI,
      params: { page_size: 4, read: true },
    },
    (respData) => respData?.results
  );

  const refetchFn = React.useCallback(async () => {
    await refetch1();
    await refetch2();
  }, [refetch1, refetch2]);

  return (
    <>
      <IconButton
        id="notifications-btn"
        title="Notifications"
        titlePlacement="bottom"
        size="sm"
        color="accent-1"
        Icon={IoMdNotifications}
      />
      {unreadNotifs?.length > 0 && (
        <Badge color="accent" className="badge-top-end-corner">
          {unreadNotifs?.length}
        </Badge>
      )}
      <UncontrolledPopover
        target="notifications-btn"
        trigger="click"
        placement="bottom-end"
        popperClassName="notifications-popover"
      >
        <Tabs
          className="mx-auto standout mt-2"
          tabTitles={["Unread", "Read"]}
          renderables={[
            // Unread
            () => (
              <Loader1
                render={() => (
                  <NotificationsList
                    notifications={unreadNotifs}
                    refetchFn={refetchFn}
                  />
                )}
              />
            ),
            // Read
            () => (
              <Loader2
                render={() => (
                  <NotificationsList
                    notifications={readNotifs}
                    refetchFn={refetchFn}
                  />
                )}
              />
            ),
          ]}
        />
      </UncontrolledPopover>
    </>
  );
}
