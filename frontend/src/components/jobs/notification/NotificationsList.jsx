import React from "react";
import PropTypes from "prop-types";
import {
  ListGroup,
  ListGroupItem,
  ListGroupItemHeading,
  ListGroupItemText,
} from "reactstrap";
import { IoCheckmarkDoneSharp } from "react-icons/io5";

import { ContentSection, IconButton, DateHoverable } from "@certego/certego-ui";
import ReactMarkdown from "react-markdown";

import { notificationMarkAsRead } from "./notificationApi";

const markdownComponents = {
  // eslint-disable-next-line id-length
  em: ({ node: _node, ...props }) => <i className="text-code" {...props} />,
  // eslint-disable-next-line id-length
  a: ({ node: _node, href, children, ...props }) => {
    // eslint-disable-next-line no-script-url
    if (href && href.startsWith("javascript:")) {
      return null;
    }
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="link-primary"
        {...props}
      >
        {children}
      </a>
    );
  },
};

markdownComponents.em.propTypes = {
  node: PropTypes.object,
};

markdownComponents.a.propTypes = {
  node: PropTypes.object,
  href: PropTypes.string,
  children: PropTypes.node,
};

export const convertHtmlToMarkdown = (htmlString) => {
  if (!htmlString) return "";

  const markdown = htmlString
    .replace(
      /<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi,
      (match, level, content) =>
        `${"#".repeat(Number(level))} ${content.trim()}\n\n`,
    )
    .replace(
      /<a[^>]*href=["']([\s\S]*?)["'][^>]*>([\s\S]*?)<\/a>/gi,
      "[$2]($1)",
    )
    .replace(/<strong[^>]*>([\s\S]*?)<\/strong>/gi, "**$1**")
    .replace(/<b[^>]*>([\s\S]*?)<\/b>/gi, "**$1**")
    .replace(/<em[^>]*>([\s\S]*?)<\/em>/gi, "*$1*")
    .replace(/<i[^>]*>([\s\S]*?)<\/i>/gi, "*$1*")
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, "`$1`")
    .replace(/<\/?[uo]l[^>]*>/gi, "")
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "- $1\n")
    .replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, "$1\n\n")
    .replace(/<br\s*\/?>/gi, "\n");
  return markdown.replace(/<[^>]*>?/gm, "");
};

export default function NotificationsList({ notifications, refetchFn }) {
  const markAsReadCb = React.useCallback(
    async (notifId) => {
      try {
        await notificationMarkAsRead(notifId);
        await refetchFn();
      } catch (error) {
        // handled inside notificationMarkAsRead
      }
    },
    [refetchFn],
  );

  return notifications.length > 0 ? (
    <ListGroup className="notifications-list">
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
            <small className="ms-auto text-muted">
              <DateHoverable value={notif?.created_at} format="p P (z)" />
            </small>
          </div>
          <ListGroupItemText className="text-light">
            <ReactMarkdown components={markdownComponents}>
              {convertHtmlToMarkdown(notif?.body)}
            </ReactMarkdown>
          </ListGroupItemText>
          <div className="d-flex">
            {notif?.read === false && (
              <IconButton
                size="xs"
                id={`notification-read-btn-${notif.id}`}
                Icon={IoCheckmarkDoneSharp}
                title="mark as read"
                className="ms-auto text-success"
                color="dark"
                outline
                onClick={() => markAsReadCb(notif.id)}
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
