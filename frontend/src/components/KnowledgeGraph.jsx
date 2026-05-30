import React, { useEffect, useState, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, RefreshCw, X, ChevronRight, Zap, Target, BookOpen, AlertTriangle } from 'lucide-react';
import client, { graphApi } from '../api/client';

export default function KnowledgeGraph() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const containerRef = useRef(null);
  const fgRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  const [selectedNode, setSelectedNode] = useState(null);
  const [showAttackPaths, setShowAttackPaths] = useState(false);
  const [attackPaths, setAttackPaths] = useState([]);
  const [selectedPathIdx, setSelectedPathIdx] = useState(0);
  const [attackPathNodes, setAttackPathNodes] = useState(new Set());
  const [attackPathLinks, setAttackPathLinks] = useState(new Set());
  const [attackPathData, setAttackPathData] = useState(null);


  // Hover states for active neighbor hover highlighting
  const [hoveredNode, setHoveredNodeState] = useState(null);
  const [hoveredNeighbors, setHoveredNeighbors] = useState(new Set());
  const [hoveredLinks, setHoveredLinks] = useState(new Set());
  const [hoveredLink, setHoveredLink] = useState(null);

  const hexToRgba = (hex, alpha = 1) => {
    if (!hex || !hex.startsWith('#')) return `rgba(255, 255, 255, ${alpha})`;
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  };

  const getRelationshipColor = (type) => {
    const rType = (type || '').toUpperCase();
    if (rType.includes('CONNECTS_TO') || rType.includes('CONNECTS')) return '#3b82f6';
    if (rType.includes('EXPLOITED_BY') || rType.includes('EXPLOIT')) return '#ef4444';
    if (rType.includes('HAS_VULNERABILITY') || rType.includes('VULNERABILITY')) return '#f43f5e';
    if (rType.includes('MAPS_TO_TECHNIQUE') || rType.includes('TECHNIQUE')) return '#818cf8';
    if (rType.includes('USED_BY') || rType.includes('USED') || rType.includes('USES')) return '#a855f7';
    if (rType.includes('AFFECTS') || rType.includes('AFFECT')) return '#f97316';
    return '#64748b';
  };

  const handleNodeHover = (node) => {
    setHoveredNodeState(node);
    const neighbors = new Set();
    const links = new Set();
    if (node) {
      graphData.links.forEach(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (s === node.id) {
          neighbors.add(t);
          links.add(l);
        } else if (t === node.id) {
          neighbors.add(s);
          links.add(l);
        }
      });
    }
    setHoveredNeighbors(neighbors);
    setHoveredLinks(links);
  };

  const handleLinkHover = (link) => {
    setHoveredLink(link);
    if (link) {
      const neighbors = new Set();
      const s = typeof link.source === 'object' ? link.source.id : link.source;
      const t = typeof link.target === 'object' ? link.target.id : link.target;
      neighbors.add(s);
      neighbors.add(t);
      setHoveredNeighbors(neighbors);
      setHoveredLinks(new Set([link]));
    } else if (!hoveredNode) {
      setHoveredNeighbors(new Set());
      setHoveredLinks(new Set());
    }
  };

  const fetchGraph = () => {
    setLoading(true);
    setSelectedNode(null);
    Promise.all([graphApi.getNodes(), graphApi.getLinks()])
      .then(([nodes, links]) => {
        setGraphData({ nodes, links });
        setLoading(false);
      })
      .catch((err) => {
        console.error("Graph fetch failed:", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchGraph();

    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight || 500
      });
    }

    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight || 500
        });
      }
    };

    // Listen for attack-paths-updated dispatched by the AI pipeline
    const handleAttackPathsUpdated = (e) => {
      if (e.detail && e.detail.paths && e.detail.paths.length > 0) {
        const newPaths = e.detail.paths;
        setAttackPaths(newPaths);
        setSelectedPathIdx(0);
        console.log('[KnowledgeGraph] Attack paths updated from pipeline:', newPaths.length);
      }
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('attack-paths-updated', handleAttackPathsUpdated);
    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('attack-paths-updated', handleAttackPathsUpdated);
    };
  }, []);


  // Fetch attack paths list when toggled
  useEffect(() => {
    if (showAttackPaths) {
      graphApi.getAttackPaths('SRV-DMZ-WEB-01', 'DB-CORE-LEDG-02')
        .then(paths => {
          if (paths && paths.length > 0) {
            setAttackPaths(paths);
            setSelectedPathIdx(0);
          } else {
            setAttackPaths([]);
            setSelectedPathIdx(0);
          }
        })
        .catch(err => {
          console.error("Error fetching attack paths:", err);
          setAttackPaths([]);
          setSelectedPathIdx(0);
        });
    } else {
      setAttackPaths([]);
      setSelectedPathIdx(0);
      setAttackPathNodes(new Set());
      setAttackPathLinks(new Set());
      setAttackPathData(null);
    }
  }, [showAttackPaths]);

  // Compute highlighting for the selected attack path index
  useEffect(() => {
    if (showAttackPaths && attackPaths.length > 0 && attackPaths[selectedPathIdx]) {
      const currentPath = attackPaths[selectedPathIdx];
      setAttackPathData(currentPath);

      const nodesInPath = new Set();
      const linksInPath = new Set();
      const links = graphData.links || [];
      const nodes = graphData.nodes || [];

      // 1. Add all asset IDs in the path
      currentPath.path_nodes.forEach(nid => {
        nodesInPath.add(nid);
      });

      // 2. Link consecutive assets in the path
      for (let i = 0; i < currentPath.path_nodes.length - 1; i++) {
        const src = currentPath.path_nodes[i];
        const tgt = currentPath.path_nodes[i + 1];
        linksInPath.add(`${src}->${tgt}`);
        linksInPath.add(`${tgt}->${src}`);
      }

      // 3. Highlight associated CVEs, Techniques, and Threat Actors
      const worstCveIds = new Set();
      if (currentPath.node_details) {
        currentPath.node_details.forEach(detail => {
          if (detail.worstCveId) {
            worstCveIds.add(detail.worstCveId);
            nodesInPath.add(detail.worstCveId);
          }
        });
      }

      // Traverse all links in the graph data
      links.forEach(link => {
        const srcId = typeof link.source === 'object' ? link.source.id : link.source;
        const tgtId = typeof link.target === 'object' ? link.target.id : link.target;

        const isAssetSrc = currentPath.path_nodes.includes(srcId);
        const isAssetTgt = currentPath.path_nodes.includes(tgtId);

        // Assets connected to their CVEs
        if (isAssetSrc && worstCveIds.has(tgtId)) {
          linksInPath.add(`${srcId}->${tgtId}`);
          linksInPath.add(`${tgtId}->${srcId}`);
        }
        if (isAssetTgt && worstCveIds.has(srcId)) {
          linksInPath.add(`${srcId}->${tgtId}`);
          linksInPath.add(`${tgtId}->${srcId}`);
        }

        // CVEs connected to Techniques
        const isCveSrc = worstCveIds.has(srcId);
        const isCveTgt = worstCveIds.has(tgtId);

        if (isCveSrc) {
          const tgtNode = nodes.find(n => n.id === tgtId);
          if (tgtNode && tgtNode.label === 'Technique') {
            nodesInPath.add(tgtId);
            linksInPath.add(`${srcId}->${tgtId}`);
            linksInPath.add(`${tgtId}->${srcId}`);
          }
        }
        if (isCveTgt) {
          const srcNode = nodes.find(n => n.id === srcId);
          if (srcNode && srcNode.label === 'Technique') {
            nodesInPath.add(srcId);
            linksInPath.add(`${srcId}->${tgtId}`);
            linksInPath.add(`${tgtId}->${srcId}`);
          }
        }
      });

      // Highlight Threat Actors using the highlighted Techniques
      links.forEach(link => {
        const srcId = typeof link.source === 'object' ? link.source.id : link.source;
        const tgtId = typeof link.target === 'object' ? link.target.id : link.target;

        const isSrcTech = nodesInPath.has(srcId) && nodes.find(n => n.id === srcId)?.label === 'Technique';
        const isTgtTech = nodesInPath.has(tgtId) && nodes.find(n => n.id === tgtId)?.label === 'Technique';

        if (isSrcTech) {
          const tgtNode = nodes.find(n => n.id === tgtId);
          if (tgtNode && tgtNode.label === 'ThreatActor') {
            nodesInPath.add(tgtId);
            linksInPath.add(`${srcId}->${tgtId}`);
            linksInPath.add(`${tgtId}->${srcId}`);
          }
        }
        if (isTgtTech) {
          const srcNode = nodes.find(n => n.id === srcId);
          if (srcNode && srcNode.label === 'ThreatActor') {
            nodesInPath.add(srcId);
            linksInPath.add(`${srcId}->${tgtId}`);
            linksInPath.add(`${tgtId}->${srcId}`);
          }
        }
      });

      setAttackPathNodes(nodesInPath);
      setAttackPathLinks(linksInPath);
    }
  }, [showAttackPaths, attackPaths, selectedPathIdx, graphData]);

  // Adjust simulation forces to repel nodes and avoid overlaps
  useEffect(() => {
    if (fgRef.current) {
      const chargeForce = fgRef.current.d3Force('charge');
      if (chargeForce) chargeForce.strength(-300);
      const linkForce = fgRef.current.d3Force('link');
      if (linkForce) linkForce.distance(140);
      fgRef.current.d3ReheatSimulation();
    }
  }, [graphData, loading]);

  const getNodeColor = (node) => {
    if (attackPathNodes.has(node.id)) {
      return '#f59e0b'; // Gold highlight for nodes in active attack path
    }

    switch (node.label) {
      case 'Asset':
        return '#3b82f6'; // Glowing Cyan/Blue
      case 'Vulnerability':
      case 'CVE':
        return '#ef4444'; // Cyber Red
      case 'Technique':
        return '#818cf8'; // Neon Purple/Blue
      case 'ThreatActor':
        return '#f97316'; // Safety Orange
      default:
        return '#a855f7'; // Purple fallback
    }
  };

  const getNodeSize = (node) => {
    let base = 8;
    if (node.label === 'Asset') {
      const crit = node.properties?.criticality || 5;
      base = 8 + crit;
    } else if (node.label === 'Vulnerability' || node.label === 'CVE') {
      const cvss = node.properties?.cvssScore || node.properties?.cvss_score || 5;
      base = 7 + cvss;
    }
    return attackPathNodes.has(node.id) ? base * 1.3 : base;
  };

  return (
    <div className="flex h-[82vh] w-full max-w-[92rem] mx-auto bg-[#0f172a]/20 border border-slate-800/80 rounded-xl overflow-hidden relative shadow-2xl" ref={containerRef}>


      {/* Extreme Right Side Panel Trigger */}
      {!showAttackPaths && (
        <button
          onClick={() => setShowAttackPaths(true)}
          className="absolute top-4 right-4 z-10 px-4 py-2 border rounded-lg text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-850 hover:border-slate-300 dark:hover:border-slate-700"
        >
          <Zap size={14} className="text-amber-600 dark:text-amber-400" />
          Check Attack Paths
        </button>
      )}

      {/* Attack Paths Side Panel */}
      <AnimatePresence>
        {showAttackPaths && (
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="absolute right-0 top-0 bottom-0 w-96 bg-slate-950/95 backdrop-blur-md border-l border-slate-200 dark:border-slate-800 shadow-2xl z-30 flex flex-col overflow-hidden"
          >
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/60">
              <div className="flex items-center gap-2">
                <Zap size={16} className="text-amber-600 dark:text-amber-400 animate-pulse" />
                <span className="text-xs font-mono font-bold tracking-widest uppercase text-amber-600 dark:text-amber-400">
                  Attack Paths
                </span>
              </div>
              <button
                onClick={() => setShowAttackPaths(false)}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800/80 rounded transition-all text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200"
              >
                <X size={16} />
              </button>
            </div>

            <div className="p-5 flex-1 overflow-y-auto">
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Predicted Vectors</h3>
              {attackPaths.length > 0 ? (
                <div className="flex flex-col gap-3">
                  <select
                    value={selectedPathIdx}
                    onChange={e => setSelectedPathIdx(parseInt(e.target.value))}
                    className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs rounded-lg px-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-amber-500 font-medium"
                  >
                    {attackPaths.map((p, idx) => (
                      <option key={idx} value={idx}>
                        Path {idx + 1} ({p.hop_count} Hops) - Risk: {p.total_risk_score}
                      </option>
                    ))}
                  </select>
                  
                  {attackPathData && (
                    <div className="mt-4 flex flex-col gap-3">
                      <div className="bg-slate-900/40 p-3.5 rounded-lg border border-slate-200 dark:border-slate-800">
                         <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block mb-2">Path Overview</span>
                         <div className="text-sm text-slate-700 dark:text-slate-300 font-mono">
                           Hops: {attackPathData.hop_count}
                         </div>
                         <div className="text-sm text-slate-700 dark:text-slate-300 font-mono">
                           Total Risk: <span className="text-red-600 dark:text-red-400 font-bold">{attackPathData.total_risk_score}</span>
                         </div>
                      </div>
                      
                      <div className="bg-slate-900/40 p-3.5 rounded-lg border border-slate-200 dark:border-slate-800">
                        <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block mb-2">Target Node</span>
                        <div className="text-sm text-slate-700 dark:text-slate-300 break-all">
                           {attackPathData.target_node}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-xs text-slate-500 dark:text-slate-500 mt-2 flex items-center gap-2">
                   <div className="w-3 h-3 border-2 border-amber-500 border-t-transparent rounded-full animate-spin"></div>
                   Loading attack paths...
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Repositioned Legend (Bottom Right) */}
      <div className="absolute bottom-4 right-4 z-10 bg-white/95 dark:bg-[#0f172a]/95 backdrop-blur-md p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 text-[10px] flex flex-col gap-2 pointer-events-none shadow-lg">
        <span className="font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-widest border-b border-slate-200 dark:border-slate-800/50 pb-1.5 mb-0.5">LEGEND</span>
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]"></span>
          <span className="text-slate-700 dark:text-slate-300">ASSETS (Hosts / Infrastructure)</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"></span>
          <span className="text-slate-700 dark:text-slate-300">VULNERABILITIES (CVEs)</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-indigo-400"></span>
          <span className="text-slate-700 dark:text-slate-300">MITRE TECHNIQUES</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
          <span className="text-slate-700 dark:text-slate-300">THREAT ACTORS</span>
        </div>
        {showAttackPaths && (
          <div className="flex items-center gap-2.5 mt-1 pt-1.5 border-t border-slate-200 dark:border-slate-800/60">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 animate-pulse shadow-[0_0_10px_rgba(245,158,11,0.8)]"></span>
            <span className="text-amber-600 dark:text-amber-400 font-bold">LATERAL ATTACK PATH</span>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3">
          <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-xs text-slate-500 dark:text-slate-600 dark:text-slate-400 tracking-widest font-mono uppercase animate-pulse">Synchronizing graph clusters from Neo4j...</span>
        </div>
      ) : (
        <div className="flex-1 relative bg-[#020617]/50 h-full">
          <ForceGraph2D
            ref={fgRef}
            graphData={graphData}
            width={dimensions.width}
            height={dimensions.height}
            nodeColor={getNodeColor}
            nodeVal={getNodeSize}
            linkLabel={link => link.type}
            linkDirectionalArrowLength={link => {
              const srcId = typeof link.source === 'object' ? link.source.id : link.source;
              const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
              const isAttackPath = showAttackPaths && attackPathLinks.has(`${srcId}->${tgtId}`);
              
              if (showAttackPaths) {
                return isAttackPath ? 10 : 0;
              }
              if (hoveredNode) {
                const isConnected = srcId === hoveredNode.id || tgtId === hoveredNode.id;
                return isConnected ? 10 : 0;
              }
              if (hoveredLink) {
                return link === hoveredLink ? 10 : 0;
              }
              return 8;
            }}
            linkDirectionalArrowColor={link => {
              const srcId = typeof link.source === 'object' ? link.source.id : link.source;
              const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
              const isAttackPath = showAttackPaths && attackPathLinks.has(`${srcId}->${tgtId}`);
              
              if (showAttackPaths) {
                return isAttackPath ? '#fbbf24' : 'rgba(148, 163, 184, 0.0)';
              }
              if (hoveredNode) {
                const isConnected = srcId === hoveredNode.id || tgtId === hoveredNode.id;
                if (!isConnected) {
                  return 'rgba(255, 255, 255, 0.0)';
                }
                return getRelationshipColor(link.type);
              }
              if (hoveredLink) {
                const isCurrentLink = link === hoveredLink;
                if (!isCurrentLink) {
                  return 'rgba(255, 255, 255, 0.0)';
                }
                return getRelationshipColor(link.type);
              }
              
              const baseColor = getRelationshipColor(link.type);
              return baseColor === '#64748b' ? 'rgba(148, 163, 184, 0.7)' : `${baseColor}dd`;
            }}
            linkDirectionalArrowRelPos={1.0}
            linkCurvature={0.15}
            onNodeHover={handleNodeHover}
            onLinkHover={handleLinkHover}
            // Animate 5 moving gold particles down active attack path links
            linkDirectionalParticles={link => {
              const srcId = typeof link.source === 'object' ? link.source.id : link.source;
              const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
              return (showAttackPaths && attackPathLinks.has(`${srcId}->${tgtId}`)) ? 5 : 0;
            }}
            linkDirectionalParticleSpeed={0.015}
            linkDirectionalParticleWidth={4.5}
            linkDirectionalParticleColor={() => '#fbbf24'}
            linkColor={link => {
              const srcId = typeof link.source === 'object' ? link.source.id : link.source;
              const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
              const isAttackPath = showAttackPaths && attackPathLinks.has(`${srcId}->${tgtId}`);

              if (showAttackPaths) {
                return isAttackPath ? '#fbbf24' : 'rgba(148, 163, 184, 0.2)';
              }

              if (hoveredNode) {
                const isConnected = srcId === hoveredNode.id || tgtId === hoveredNode.id;
                if (!isConnected) {
                  return 'rgba(255, 255, 255, 0.05)';
                }
                return getRelationshipColor(link.type);
              }

              if (hoveredLink) {
                const isCurrentLink = link === hoveredLink;
                if (!isCurrentLink) {
                  return 'rgba(255, 255, 255, 0.05)';
                }
                return getRelationshipColor(link.type);
              }

              const baseColor = getRelationshipColor(link.type);
              return baseColor === '#64748b' ? 'rgba(148, 163, 184, 0.7)' : `${baseColor}dd`;
            }}
            linkWidth={link => {
              const srcId = typeof link.source === 'object' ? link.source.id : link.source;
              const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
              const isAttackPath = showAttackPaths && attackPathLinks.has(`${srcId}->${tgtId}`);

              if (showAttackPaths) {
                return isAttackPath ? 4.5 : 0.8;
              }
              if (hoveredNode) {
                const isConnected = srcId === hoveredNode.id || tgtId === hoveredNode.id;
                return isConnected ? 3.5 : 0.8;
              }
              if (hoveredLink) {
                return link === hoveredLink ? 4.0 : 0.8;
              }
              return 2.2;
            }}
            onNodeClick={(node) => {
              setSelectedNode(node);
            }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name || node.id;
              const fontSize = 13 / globalScale;
              ctx.font = `bold ${fontSize}px 'Outfit', sans-serif`;

              const size = getNodeSize(node);
              const isHovered = hoveredNode && node.id === hoveredNode.id;
              const isNeighbor = hoveredNode && hoveredNeighbors.has(node.id);
              const hasHover = hoveredNode !== null;

              // Dim nodes if showAttackPaths is active or under hover
              let opacity = 1.0;
              if (showAttackPaths) {
                opacity = attackPathNodes.has(node.id) ? 1.0 : 0.12;
              } else if (hasHover && !isHovered && !isNeighbor) {
                opacity = 0.15;
              }

              // Draw node selection/hover border glow shadow
              if (isHovered || (selectedNode && node.id === selectedNode.id)) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, size + 5, 0, 2 * Math.PI, false);
                ctx.fillStyle = isHovered ? 'rgba(34, 211, 238, 0.25)' : 'rgba(59, 130, 246, 0.25)';
                ctx.fill();
              }

              // Base filled node with opacity
              ctx.beginPath();
              ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
              ctx.fillStyle = hexToRgba(getNodeColor(node), opacity);
              ctx.fill();

              // Draw pulsing rings around path nodes
              if (attackPathNodes.has(node.id)) {
                const pulsePeriod = 1500; // 1.5 seconds cycle
                const t = (Date.now() % pulsePeriod) / pulsePeriod; // 0 to 1
                const pulseRadius = size + 4 + Math.sin(t * Math.PI * 2) * 2;
                const pulseOpacity = 0.4 + Math.sin(t * Math.PI * 2) * 0.3;

                ctx.beginPath();
                ctx.arc(node.x, node.y, pulseRadius, 0, 2 * Math.PI, false);
                ctx.strokeStyle = hexToRgba('#f59e0b', opacity * pulseOpacity);
                ctx.lineWidth = 2.5;
                ctx.stroke();
              } else if (node.label === 'Asset') {
                ctx.beginPath();
                ctx.arc(node.x, node.y, size + 3, 0, 2 * Math.PI, false);
                ctx.strokeStyle = hexToRgba('#3b82f6', opacity * 0.4);
                ctx.lineWidth = 1.5;
                ctx.stroke();
              }

              // Node text label with high contrast dark card backing
              if (globalScale > 0.6) {
                const textWidth = ctx.measureText(label).width;
                const padX = 8 / globalScale;
                const padY = 5 / globalScale;
                const rectW = textWidth + padX * 2;
                const rectH = fontSize + padY * 2;
                const rectX = node.x - rectW / 2;
                const rectY = node.y - size - rectH - (5 / globalScale);

                const radius = 4 / globalScale;
                ctx.beginPath();
                ctx.moveTo(rectX + radius, rectY);
                ctx.lineTo(rectX + rectW - radius, rectY);
                ctx.quadraticCurveTo(rectX + rectW, rectY, rectX + rectW, rectY + radius);
                ctx.lineTo(rectX + rectW, rectY + rectH - radius);
                ctx.quadraticCurveTo(rectX + rectW, rectY + rectH, rectX + rectW - radius, rectY + rectH);
                ctx.lineTo(rectX + radius, rectY + rectH);
                ctx.quadraticCurveTo(rectX, rectY + rectH, rectX, rectY + rectH - radius);
                ctx.lineTo(rectX, rectY + radius);
                ctx.quadraticCurveTo(rectX, rectY, rectX + radius, rectY);
                ctx.closePath();

                // Dark background card
                ctx.fillStyle = `rgba(15, 23, 42, ${opacity * 0.95})`;
                ctx.fill();

                // Border glow on label
                ctx.strokeStyle = isHovered
                  ? `rgba(34, 211, 238, ${opacity * 0.8})`
                  : (selectedNode && node.id === selectedNode.id)
                    ? `rgba(59, 130, 246, ${opacity * 0.8})`
                    : `rgba(51, 65, 85, ${opacity * 0.45})`;
                ctx.lineWidth = isHovered || (selectedNode && node.id === selectedNode.id) ? 1.5 / globalScale : 1.0 / globalScale;
                ctx.stroke();

                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';

                // Color code text font inside label
                if (attackPathNodes.has(node.id)) {
                  ctx.fillStyle = hexToRgba('#fbbf24', opacity);
                } else if (node.label === 'Vulnerability' || node.label === 'CVE') {
                  ctx.fillStyle = hexToRgba('#fca5a5', opacity);
                } else {
                  ctx.fillStyle = hexToRgba('#e2e8f0', opacity);
                }

                ctx.fillText(label, node.x, rectY + rectH / 2);
              }
            }}
          />
        </div>
      )}

      {/* Slide-out details drawer panel */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="absolute right-0 top-0 bottom-0 w-96 bg-slate-950/95 backdrop-blur-md border-l border-slate-200 dark:border-slate-800 shadow-2xl z-20 flex flex-col overflow-hidden"
          >
            {/* Drawer Header */}
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/60">
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${selectedNode.label === 'Asset' ? 'bg-blue-500' :
                  selectedNode.label === 'Vulnerability' || selectedNode.label === 'CVE' ? 'bg-red-500' : 'bg-indigo-400'
                  }`}></div>
                <span className="text-xs font-mono font-bold tracking-widest uppercase text-slate-500 dark:text-slate-600 dark:text-slate-400">
                  {selectedNode.label} Profile
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800/80 rounded transition-all text-slate-500 dark:text-slate-600 dark:text-slate-400 hover:text-slate-200"
              >
                <X size={16} />
              </button>
            </div>

            {/* Drawer Body Content */}
            <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-6">
              <div>
                <h3 className="text-xl font-bold text-white tracking-tight leading-snug">
                  {selectedNode.properties?.name || selectedNode.name || selectedNode.id}
                </h3>
                <span className="text-xs font-mono text-slate-500 dark:text-slate-500 mt-1 block">ID: {selectedNode.id}</span>
              </div>

              {/* Conditional Rendering by Node Label */}
              {selectedNode.label === 'Asset' && (
                <div className="flex flex-col gap-4">
                  <div className="grid grid-cols-2 gap-3.5 bg-slate-900/40 p-3.5 rounded-lg border border-slate-900">
                    <div>
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">Criticality</span>
                      <span className="text-base font-extrabold text-cyan-600 dark:text-cyan-400 font-mono">
                        {selectedNode.properties?.criticality || '5'} / 10
                      </span>
                    </div>
                    <div>
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">Exposure</span>
                      <span className="text-base font-extrabold text-slate-700 dark:text-slate-300 font-mono capitalize">
                        {selectedNode.properties?.exposure || 'Internal'}
                      </span>
                    </div>
                    <div className="col-span-2 pt-2.5 border-t border-slate-800/40">
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">Role Type</span>
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 capitalize">
                        {selectedNode.properties?.type || 'Host'}
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-col gap-2">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400 uppercase tracking-widest">Network Placement</span>
                    <div className="text-sm text-slate-500 dark:text-slate-600 dark:text-slate-400 flex flex-col gap-2 font-mono bg-slate-900/20 p-3.5 rounded border border-slate-900">
                      <div>Environment: <span className="text-slate-800 dark:text-slate-200">{selectedNode.properties?.environment || 'Production'}</span></div>
                      <div>System Owner: <span className="text-slate-800 dark:text-slate-200">{selectedNode.properties?.owner || 'SOC Ops Team'}</span></div>
                    </div>
                  </div>
                </div>
              )}

              {(selectedNode.label === 'Vulnerability' || selectedNode.label === 'CVE') && (
                <div className="flex flex-col gap-4">
                  <div className="grid grid-cols-2 gap-3 bg-slate-900/40 p-3.5 rounded-lg border border-slate-900">
                    <div>
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">CVSS Score</span>
                      <span className="text-base font-extrabold text-red-600 dark:text-red-400 font-mono">
                        {selectedNode.properties?.cvssScore || selectedNode.properties?.cvss_score || 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">EPSS Probability</span>
                      <span className="text-base font-extrabold text-amber-500 font-mono">
                        {selectedNode.properties?.epssScore ? `${(selectedNode.properties.epssScore * 100).toFixed(2)}%` : 'N/A'}
                      </span>
                    </div>
                    <div className="col-span-2 pt-2.5 border-t border-slate-800/40">
                      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold block">KEV Active Exploit</span>
                      <span className={`text-sm font-bold font-mono ${selectedNode.properties?.isKEV || selectedNode.properties?.is_kev ? 'text-red-500 animate-pulse' : 'text-slate-500 dark:text-slate-600 dark:text-slate-400'
                        }`}>
                        {selectedNode.properties?.isKEV || selectedNode.properties?.is_kev ? '⚠️ KNOWN EXPLOITED' : 'None Mapped'}
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-col gap-2">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400 uppercase tracking-widest">Vulnerability Abstract</span>
                    <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-900/20 p-3.5 rounded border border-slate-900 font-serif">
                      {selectedNode.properties?.description || 'No description summary available.'}
                    </p>
                  </div>
                </div>
              )}

              {selectedNode.label === 'Technique' && (
                <div className="flex flex-col gap-4">
                  <div className="bg-slate-900/40 p-3.5 rounded-lg border border-slate-900 flex flex-col gap-1.5">
                    <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold">Tactic Classification</span>
                    <span className="text-sm font-bold text-indigo-400 capitalize">
                      {selectedNode.properties?.tactic || 'Execution'}
                    </span>
                  </div>

                  <div className="flex flex-col gap-2">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400 uppercase tracking-widest">MITRE Description</span>
                    <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-900/20 p-3.5 rounded border border-slate-900">
                      {selectedNode.properties?.description || 'No details available.'}
                    </p>
                  </div>
                </div>
              )}

              {selectedNode.label === 'ThreatActor' && (
                <div className="flex flex-col gap-4">
                  <div className="bg-slate-900/40 p-3.5 rounded-lg border border-slate-900 flex flex-col gap-1.5">
                    <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-500 font-semibold font-mono">Origin Segment</span>
                    <span className="text-sm font-bold text-orange-400 font-mono">
                      {selectedNode.properties?.origin || 'Unknown'}
                    </span>
                  </div>

                  <div className="flex flex-col gap-2">
                    <span className="text-xs font-semibold text-slate-500 dark:text-slate-600 dark:text-slate-400 uppercase tracking-widest">Actor Dossier</span>
                    <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-900/20 p-3.5 rounded border border-slate-900 font-mono">
                      {selectedNode.properties?.description || 'No threat intelligence profile has been generated.'}
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Drawer Footer Actions */}
            <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-900/40 flex flex-col">
              <button
                onClick={() => setSelectedNode(null)}
                className="py-3 bg-slate-850 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all"
              >
                Close Drawer
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
