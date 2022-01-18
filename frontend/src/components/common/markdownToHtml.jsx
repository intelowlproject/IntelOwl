import React from "react";
import ReactMarkdown from "react-markdown";

export default function markdownToHtml(text) {
  return (
    <ReactMarkdown
      // eslint-disable-next-line react/no-children-prop
      children={text}
      components={{
        em: ({ node, ...props }) => <i className="text-code" {...props} />,
        a: ({ node, ...props }) => (
          // eslint-disable-next-line jsx-a11y/anchor-has-content
          <a target="_blank" className="link-primary" {...props} />
        ),
      }}
    />
  );
}
