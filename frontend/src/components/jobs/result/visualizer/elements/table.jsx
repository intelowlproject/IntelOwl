import React from "react";
import PropTypes from "prop-types";
import { DataTable } from "@certego/certego-ui";

export function TableVisualizer({ id, size, columns, data }) {
  const tableColumns = [];

  columns.forEach((column) => {
    const columnHeader = column.replaceAll("_", " ");
    tableColumns.push({
      Header: columnHeader,
      id: column,
      accessor: column,
      disableSortBy: true,
    });
  });

  const tableConfig = {};
  const tableInitialState = {
    pageSize: 6,
  };

  return (
    <div className={size} style={{ height: "30%", overflow: "scroll" }}>
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
