import React from "react";
import ReactMarkdown from "react-markdown";

/**
 * @param {string} text
 */
export function markdownToHtml(text) {
  return (
    <ReactMarkdown
      // eslint-disable-next-line react/no-children-prop
      children={text}
      components={{
        // eslint-disable-next-line id-length
        em: ({ node: _, ...props }) => <i className="text-code" {...props} />,
        // eslint-disable-next-line id-length
        a: ({ node: _, ...props }) => (
          // eslint-disable-next-line jsx-a11y/anchor-has-content
          <a target="_blank" className="link-primary" {...props} />
        ),
      }}
    />
  );
}
