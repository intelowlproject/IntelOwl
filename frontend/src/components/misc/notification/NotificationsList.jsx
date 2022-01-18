import React from "react";
import PropTypes from "prop-types";
import {
  ListGroup,
  ListGroupItem,
  ListGroupItemHeading,
  ListGroupItemText
} from "reactstrap";
import Moment from "react-moment";
import { IoCheckmarkDoneSharp } from "react-icons/io5";

import { ContentSection, IconButton } from "@certego/certego-ui";

import { notificationMarkAsRead } from "./api";

export default function NotificationsList({ notifications, refetchFn, }) {
  const markAsReadCb = React.useCallback(
    async (notifId) => {
      try {
        await notificationMarkAsRead(notifId);
        await refetchFn();
      } catch (e) {
        // handled inside notificationMarkAsRead
      }
    },
    [refetchFn]
  );

  return notifications.length > 0 ? (
    <ListGroup>
      {notifications.map((notif) => (
        <ListGroupItem
          tag={ContentSection}
          key={`notification-${notif.id}`}
          className="bg-darker m-1"
        >
          <div className="d-flex-start-center border-bottom border-dark mb-2">
            <ListGroupItemHeading className="text-info">
              {notif?.title}
            </ListGroupItemHeading>
            <small className="ml-auto text-muted">
              <Moment
                date={notif?.created_at}
                format="hh:mm ddd DD MMM YYYY (Z)"
              />
            </small>
          </div>
          <ListGroupItemText
            dangerouslySetInnerHTML={{ __html: notif?.body, }}
          />
          <div className="d-flex">
            {notif?.read === false && (
              <IconButton
                size="xs"
                Icon={IoCheckmarkDoneSharp}
                title="mark as read"
                className="ml-auto text-success"
                color="dark"
                outline
                onClick={() => markAsReadCb(notif?.id)}
              />
            )}
          </div>
        </ListGroupItem>
      ))}
    </ListGroup>
  ) : (
    <h6 className="mt-1 text-center text-muted">No items</h6>
  );
}

NotificationsList.propTypes = {
  notifications: PropTypes.array.isRequired,
  refetchFn: PropTypes.func.isRequired,
};
