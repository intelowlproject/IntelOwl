import { MarkerType } from "reactflow";
import { getLayoutedElements } from "../../common/flows/getLayoutedElements";

/* eslint-disable id-length */
function addNode(
  nodesList,
  edgesList,
  nodeType,
  nodeToAdd,
  pivotsStored,
  playbooksStored,
) {
  const node = {
    id: `${nodeType}-${nodeToAdd.id}`,
    data: {
      id: nodeToAdd.id,
      label: nodeToAdd.name,
    },
    draggable: false,
  };

  if (nodeType === "pivot") {
    node.type = "pivotNode";
    node.data = {
      ...node.data,
      analyzers: nodeToAdd?.related_analyzer_configs?.toString(),
      connectors: nodeToAdd?.related_connector_configs?.toString(),
      type: nodeToAdd?.python_module,
      fieldToCompare: nodeToAdd?.params?.field_to_compare?.value,
    };
  } else {
    node.type = "playbookNode";
    node.data = {
      ...node.data,
      description: nodeToAdd?.description,
      configured: nodeToAdd?.configured,
    };
  }
  nodesList.push(node);

  // recursive call if there are children
  if (nodeToAdd.pivots) {
    nodeToAdd.pivots.forEach((child) => {
      const pivotConfig = pivotsStored.find((plugin) => plugin.name === child);
      addNode(
        nodesList,
        edgesList,
        "pivot",
        pivotConfig,
        pivotsStored,
        playbooksStored,
      );
      // add edge
      edgesList.push({
        id: `edge-${nodeType}${nodeToAdd.id}-pivot${pivotConfig.id}`,
        source: `${nodeType}-${nodeToAdd.id}`,
        target: `pivot-${pivotConfig.id}`,
      });
    });
  } else if (nodeToAdd.playbooks_choice) {
    nodeToAdd.playbooks_choice.forEach((child) => {
      let playbookConfig = {};
      playbookConfig = playbooksStored.find((plugin) => plugin.name === child);
      if (playbookConfig === undefined) {
        playbookConfig = {};
        playbookConfig.id = `${child}`;
        playbookConfig.name = child;
        playbookConfig.description =
          "The playbook is not enabled or configured for this user.";
        playbookConfig.pivots = [];
        playbookConfig.configured = false;

        // set warning in the current pivot, it will always fail
        const pivotIndex = nodesList.findIndex(
          (pivotNode) => pivotNode.id === `${nodeType}-${nodeToAdd.id}`,
        );
        const pivotNode = nodesList[pivotIndex];
        pivotNode.data.warning = true;
      } else {
        playbookConfig.configured = true;
      }
      addNode(
        nodesList,
        edgesList,
        "playbook",
        playbookConfig,
        pivotsStored,
        playbooksStored,
      );
      // add edge
      edgesList.push({
        id: `edge-${nodeType}${nodeToAdd.id}-playbook${playbookConfig.id}`,
        source: `${nodeType}-${nodeToAdd.id}`,
        target: `playbook-${playbookConfig.id}`,
        markerEnd: {
          type: MarkerType.ArrowClosed,
        },
      });
    });
  }
}

export function getNodesAndEdges(playbook, pivotsStored, playbooksStored) {
  // nodes
  const initialNode = [
    {
      id: `playbook-${playbook.id}`,
      position: { x: 0, y: 0 },
      data: {
        id: playbook.id,
        label: playbook.name,
        description: playbook.description,
        configured: true,
      },
      type: "playbookNode",
      draggable: false,
    },
  ];
  const nodes = [];

  // edges
  const initialEdges = [];
  const edges = [];

  if (playbook.pivots.length) {
    playbook.pivots.forEach((pivotToExecute) => {
      const pivotConfig = pivotsStored.find(
        (plugin) => plugin.name === pivotToExecute,
      );
      addNode(
        nodes,
        edges,
        "pivot",
        pivotConfig,
        pivotsStored,
        playbooksStored,
      );
      edges.push({
        id: `edge-playbook${playbook.id}-pivot${pivotConfig.id}`,
        source: `playbook-${playbook.id}`,
        target: `pivot-${pivotConfig.id}`,
      });
    });
  }

  if (edges.length) {
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      initialNode.concat(nodes),
      initialEdges.concat(edges),
      300,
      60,
      50,
      50,
    );
    return [layoutedNodes, layoutedEdges];
  }

  initialNode[0].position = { x: 50, y: 30 };
  return [initialNode, initialEdges];
}
