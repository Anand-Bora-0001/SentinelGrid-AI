import React, { useMemo } from 'react';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';

const nodeStyle = {
  background: '#0f172a',
  color: '#cbd5e1',
  border: '1px solid #1e293b',
  borderRadius: '8px',
  padding: '12px',
  fontSize: '12px',
  fontFamily: 'monospace',
  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.5)'
};

const highlightStyle = {
  ...nodeStyle,
  background: '#1e1b4b',
  border: '1px solid #6366f1',
  boxShadow: '0 0 15px rgba(99, 102, 241, 0.4)'
};

export default function AttackChainVisualization({ chainStages = [] }) {
  const { nodes, edges } = useMemo(() => {
    if (!chainStages || chainStages.length === 0) {
      return { nodes: [], edges: [] };
    }

    const n = [];
    const e = [];

    chainStages.forEach((stage, index) => {
      // Is it a string (just tactic) or object?
      const tactic = typeof stage === 'string' ? stage : stage.tactic;
      const techName = typeof stage === 'object' ? stage.technique_name : '';
      
      const row = Math.floor(index / 4);
      const col = index % 4;
      const posX = col * 220;
      const posY = row * 150 + 30;

      let sourcePos = 'right';
      let targetPos = 'left';

      if (col === 3) {
        sourcePos = 'bottom';
      }
      if (col === 0 && index > 0) {
        targetPos = 'top';
      }

      n.push({
        id: `node-${index}`,
        data: { 
          label: (
            <div className="flex flex-col items-center text-center w-[150px]">
              <strong className="text-cyber-cyan uppercase text-[10px] tracking-wider">{tactic}</strong>
              {techName && <span className="text-[9px] text-slate-400 mt-1 truncate w-full" title={techName}>{techName}</span>}
            </div>
          ) 
        },
        position: { x: posX, y: posY },
        style: highlightStyle,
        sourcePosition: sourcePos,
        targetPosition: targetPos
      });

      if (index > 0) {
        const prevCol = (index - 1) % 4;
        const isRowChange = (prevCol === 3);

        e.push({
          id: `edge-${index - 1}-${index}`,
          source: `node-${index - 1}`,
          target: `node-${index}`,
          animated: true,
          type: isRowChange ? 'smoothstep' : 'default',
          style: { stroke: '#6366f1', strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#6366f1',
          },
        });
      }
    });

    return { nodes: n, edges: e };
  }, [chainStages]);

  if (!chainStages || chainStages.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 font-mono text-xs">
        No attack chain data available
      </div>
    );
  }

  return (
    <div style={{ height: '100%', width: '100%' }}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background color="#1e293b" gap={16} />
        <Controls style={{ background: '#0f172a', border: '1px solid #1e293b', fill: '#cbd5e1' }} />
      </ReactFlow>
    </div>
  );
}
