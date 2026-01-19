import React from "react";
import PropTypes from "prop-types";
import { UncontrolledTooltip } from "reactstrap";
import { DataTable, DefaultColumnFilter } from "@certego/certego-ui";

import { VerticalListVisualizer } from "./verticalList";
import { HorizontalListVisualizer } from "./horizontalList";
import { markdownToHtml } from "../../markdownToHtml";

function getAccessor(element) {
  if ([VerticalListVisualizer, HorizontalListVisualizer].includes(element.type))
    // recursive call
    return element.props.values.map((val) => getAccessor(val)).flat();
  return element.props.value;
}

export function TableVisualizer({ id, size, columns, data, pageSize, sortBy }) {
  const tableColumns = [];

  columns.forEach((column) => {
    const columnHeader = column.name.replaceAll("_", " ");
    const columnElement = (
      <>
        <span id={`${column.name}-header`}>{columnHeader}</span>
        {column.description && (
          <UncontrolledTooltip
            target={`${column.name}-header`}
            placement="top"
            fade={false}
            style={{
              paddingTop: "1rem",
              paddingLeft: "1rem",
              paddingRight: "1rem",
            }}
          >
            {markdownToHtml(column.description)}
          </UncontrolledTooltip>
        )}
      </>
    );

    tableColumns.push({
      Header: columnElement,
      id: column.name,
      accessor: (row) => getAccessor(row[column.name]),
      Cell: ({
        cell: {
          row: { original },
        },
      }) => original[column.name],
      disableFilters: column.disableFilters,
      disableSortBy: column.disableSortBy,
      Filter: DefaultColumnFilter,
      maxWidth: column.maxWidth,
    });
  });

  const tableConfig = {};
  const tableInitialState = {
    pageSize,
    sortBy,
  };

  return (
    <div
      id={id}
      className={size}
      style={{ maxHeight: "80vh", overflowY: "scroll" }}
    >
      <DataTable
        id={id}
        data={data}
        config={tableConfig}
        initialState={tableInitialState}
        columns={tableColumns}
      />
    </div>
  );
}

TableVisualizer.propTypes = {
  id: PropTypes.string.isRequired,
  size: PropTypes.string.isRequired,
  columns: PropTypes.arrayOf(PropTypes.object).isRequired,
  data: PropTypes.array.isRequired,
  pageSize: PropTypes.number,
  sortBy: PropTypes.array,
};

TableVisualizer.defaultProps = {
  pageSize: 5,
  sortBy: [],
};
