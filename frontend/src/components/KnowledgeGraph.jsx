import React, { useEffect, useState, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { graphApi } from '../api/client';

export default function KnowledgeGraph({ onSelectNode }) {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });

  const fetchGraph = () => {
    setLoading(true);
    Promise.all([graphApi.getNodes(), graphApi.getLinks()])
      .then(([nodes, links]) => {
        setGraphData({ nodes, links });
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchGraph();
    
    // Resize observer to scale graph width and height smoothly
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight || 400
      });
    }

    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight || 400
        });
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const getNodeColor = (node) => {
    switch (node.label) {
      case 'Asset':
        return '#06b6d4'; // Glowing Cyan
      case 'Vulnerability':
        return '#f43f5e'; // Cyber Rose Red
      case 'Technique':
        return '#818cf8'; // Neon Purple/Blue
      default:
        return '#94a3b8';
    }
  };

  return (
    <div className="flex-1 glass-panel rounded-xl overflow-hidden flex flex-col relative" ref={containerRef}>
      <div className="px-6 py-4 border-b border-cyber-border flex justify-between items-center bg-slate-900/40 z-10">
        <div>
          <h2 className="text-sm font-bold tracking-wider uppercase text-cyan-400">Cyber Knowledge Graph</h2>
          <p className="text-[10px] text-slate-400 mt-0.5">Asset topology, active vulnerabilities &amp; MITRE mappings</p>
        </div>
        <button 
          onClick={fetchGraph}
          className="px-3 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 rounded-lg text-xs font-semibold text-cyan-400 transition-all"
        >
          SYNC GRAPH
        </button>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-xs text-slate-400 font-medium">Synchronizing nodes from Neo4j...</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 relative bg-slate-950/20">
          <ForceGraph2D
            graphData={graphData}
            width={dimensions.width}
            height={dimensions.height}
            nodeColor={getNodeColor}
            nodeVal={node => node.label === 'Asset' ? 6 : 4}
            linkLabel={link => link.type}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkCurvature={0.15}
            linkColor={() => 'rgba(255, 255, 255, 0.15)'}
            onNodeClick={(node) => {
              if (onSelectNode) onSelectNode(node);
            }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name || node.id;
              const fontSize = 12 / globalScale;
              ctx.font = `${fontSize}px Outfit, sans-serif`;
              
              // Draw node dot
              const size = node.label === 'Asset' ? 5 : 3.5;
              ctx.beginPath();
              ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
              ctx.fillStyle = getNodeColor(node);
              ctx.fill();
              
              // Add a glow ring for Asset nodes
              if (node.label === 'Asset') {
                ctx.beginPath();
                ctx.arc(node.x, node.y, size + 2, 0, 2 * Math.PI, false);
                ctx.strokeStyle = 'rgba(6, 182, 212, 0.2)';
                ctx.lineWidth = 1;
                ctx.stroke();
              }

              // Text labeling
              const textWidth = ctx.measureText(label).width;
              const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2); 
              
              ctx.fillStyle = 'rgba(3, 7, 18, 0.6)';
              ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - size - fontSize * 1.2, bckgDimensions[0], bckgDimensions[1]);
              
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = node.label === 'Vulnerability' ? '#fca5a5' : '#e2e8f0';
              ctx.fillText(label, node.x, node.y - size - fontSize * 0.7);
            }}
          />
          
          {/* Map Legend overlay */}
          <div className="absolute bottom-4 left-4 p-3 bg-slate-900/80 backdrop-blur-md rounded-lg border border-cyber-border text-[10px] flex flex-col gap-2 pointer-events-none">
            <span className="font-semibold text-slate-400 uppercase tracking-wider">Legend</span>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 shadow-glow-cyan"></span>
              <span>ASSETS (Hosts/Routers)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-glow-red"></span>
              <span>VULNERABILITIES (CVEs)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-indigo-400"></span>
              <span>MITRE ATT&amp;CK Techniques</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
