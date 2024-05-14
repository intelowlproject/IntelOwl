import React from "react";
import PropTypes from "prop-types";
import { DataTable, DefaultColumnFilter } from "@certego/certego-ui";

import { VerticalListVisualizer } from "./verticalList";

export function TableVisualizer({ id, size, columns, data }) {
  const tableColumns = [];

  columns.forEach((column) => {
    const columnHeader = column.replaceAll("_", " ");
    tableColumns.push({
      Header: columnHeader,
      id: column,
      accessor: (row) =>
        row[column].type === VerticalListVisualizer
          ? row[column].props.values.map((val) => val.props.value)
          : row[column].props.value,
      Cell: ({
        cell: {
          row: { original },
        },
      }) => original[column],
      disableSortBy: true,
      Filter: DefaultColumnFilter,
    });
  });

  const tableConfig = {};
  const tableInitialState = {
    pageSize: 6,
  };

  return (
    <div className={size} style={{ maxHeight: "60vh", overflowY: "scroll" }}>
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
  columns: PropTypes.arrayOf(PropTypes.string).isRequired,
  data: PropTypes.arrayOf(PropTypes.element).isRequired,
};
