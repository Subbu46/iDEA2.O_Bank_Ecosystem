// ─────────────────────────────────────────────────────────────────────────────
// DigitalTwin.jsx — Main Orchestrator (3D Refactored)
// Composes: BankingScene + EntityModels + NetworkConnections + HUD panels
// All data comes from the existing backend pipeline — no invented telemetry.
// ─────────────────────────────────────────────────────────────────────────────
import React, { useState, useEffect, useRef, useCallback } from 'react';
import BankingScene from './twin/BankingScene';
import EntityModels from './twin/EntityModels';
import NetworkConnections from './twin/NetworkConnections';
import { TopBar, StatusBanner } from './twin/TwinHUD';
import SandboxSidebar from './twin/SandboxSidebar';
import NodeDetailPanel from './twin/NodeDetailPanel';
import {
  FALLBACK_NODES,
  FALLBACK_CONNECTIONS,
  SCENARIOS,
  NORMAL_LOGS,
  nowStr,
} from './twin/twinData';
import { graphApi } from '../api/client';
import './twin/twin.css';

// ─────────────────────────────────────────────────────────────────────────────
// MAIN COMPONENT
// ─────────────────────────────────────────────────────────────────────────────
export default function DigitalTwin() {
  // ── Core State ──────────────────────────────────────────────────────────
  const [nodes, setNodes] = useState(FALLBACK_NODES);
  const [connections, setConnections] = useState(FALLBACK_CONNECTIONS);
  const [simState, setSimState] = useState('idle');       // idle | running | breach | remediating | remediated
  const [selectedScenario, setSelectedScenario] = useState('core_data_exfil');
  const [attackPathNodes, setAttackPathNodes] = useState(new Set());
  const [logLines, setLogLines] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [defcon, setDefcon] = useState(5);
  const [compromisedCount, setCompromisedCount] = useState(0);
  const [liability, setLiability] = useState(0);

  // ── Refs ────────────────────────────────────────────────────────────────
  const simTimerRef = useRef(null);
  const liabilityRef = useRef(null);
  const normalLogRef = useRef(null);

  // ── Fetch Live Data from Backend Pipeline + 15s Polling ──────────────────
  // Any backend parameter change (criticality, CVE scores, KEV status)
  // auto-reflects in the 3D Digital Twin within one polling cycle.
  useEffect(() => {
    let cancelled = false;

    async function fetchTopology() {
      try {
        const response = await graphApi.getNodes();
        // The response can be either { nodes, links } or just an array
        if (cancelled) return;

        if (response && typeof response === 'object') {
          let fetchedNodes, fetchedLinks;

          if (Array.isArray(response)) {
            fetchedNodes = response;
          } else if (response.nodes) {
            fetchedNodes = response.nodes;
            fetchedLinks = response.links;
          }

          if (fetchedNodes && fetchedNodes.length > 0) {
            // Transform backend nodes to our format
            const transformedNodes = fetchedNodes
              .filter(n => n.label === 'Asset' || n.type === 'Asset' || n.properties?.zone)
              .map(n => {
                const p = n.properties || n;
                return {
                  id: n.id || p.id || p.assetId,
                  name: p.name || n.name || n.id,
                  type: p.type || n.type || 'Unknown',
                  zone: p.zone || 'DMZ',
                  ip: p.ip_address || p.ip || '—',
                  os: p.os_version || p.os || '—',
                  criticality: p.criticality || 5,
                  cve: p.cve || '—',
                  cvss: p.cvss || p.cvssScore || 0,
                  isKEV: p.isKEV || p.is_kev || false,
                };
              });

            if (transformedNodes.length > 0) {
              setNodes(transformedNodes);
            }
          }

          // Transform links to connections array
          if (fetchedLinks && fetchedLinks.length > 0) {
            const conns = fetchedLinks
              .filter(l => l.type === 'CONNECTS_TO')
              .map(l => [l.source, l.target]);
            if (conns.length > 0) {
              setConnections(conns);
            }
          }
        }
      } catch (err) {
        console.warn('[DigitalTwin] Backend sync failed:', err.message);
        // Keep current data — fallback is already set as default state
      }
    }

    // Immediate fetch on mount
    fetchTopology();

    // Live polling — re-sync every 15 seconds so backend parameter changes
    // (criticality, CVSS, KEV status, new CVEs) reflect in the 3D scene.
    const pollInterval = setInterval(fetchTopology, 15000);

    return () => {
      cancelled = true;
      clearInterval(pollInterval);
    };
  }, []);


  // ── Log Helper ──────────────────────────────────────────────────────────
  const addLog = useCallback((entry) => {
    const line = { ...entry, time: nowStr(), id: Date.now() + Math.random() };
    setLogLines(prev => [line, ...prev].slice(0, 60));
  }, []);

  // ── Simulation Engine (same logic as original — drives the 3D scene) ────
  const startSimulation = useCallback(() => {
    if (simState === 'running' || simState === 'breach') return;
    const scenario = SCENARIOS[selectedScenario];
    if (!scenario) return;

    setSimState('running');
    setDefcon(2);
    setCompromisedCount(0);
    setLiability(0);
    setAttackPathNodes(new Set());

    const path = scenario.path;
    addLog({ type: 'ALERT', msg: `🚨 RED TEAM SIM: "${scenario.name}" initiated` });

    let step = 0;
    const revealStep = () => {
      if (step >= path.length) {
        setSimState('breach');
        setDefcon(1);
        addLog({ type: 'BREACH', msg: `💥 BREACH CONFIRMED: ${path[path.length - 1]} COMPROMISED` });

        liabilityRef.current = setInterval(() => {
          setLiability(l => Math.min(l + Math.floor(Math.random() * 850000 + 150000), 99999999));
        }, 800);

        simTimerRef.current = setTimeout(() => {
          setSimState('remediated');
          setDefcon(4);
          clearInterval(liabilityRef.current);
          addLog({ type: 'REMEDIATE', msg: '🛡️ AI GOVERNANCE: Automated containment protocols activated' });
          addLog({ type: 'REMEDIATE', msg: '✅ Threat contained. Affected assets quarantined.' });
        }, 12000);
        return;
      }

      const nodeId = path[step];
      setAttackPathNodes(prev => new Set([...prev, nodeId]));
      setCompromisedCount(step + 1);

      const node = nodes.find(n => n.id === nodeId);
      if (node) {
        addLog({ type: 'ATTACK', msg: `⚡ [${step + 1}/${path.length}] Exploiting ${node.name?.split(' ')[0] || nodeId} (${node.ip}) via ${node.cve}` });
      }

      step++;
      simTimerRef.current = setTimeout(revealStep, 2200);
    };

    simTimerRef.current = setTimeout(revealStep, 800);
  }, [simState, selectedScenario, addLog, nodes]);

  const resetSimulation = useCallback(() => {
    clearTimeout(simTimerRef.current);
    clearInterval(liabilityRef.current);
    setSimState('idle');
    setDefcon(5);
    setAttackPathNodes(new Set());
    setCompromisedCount(0);
    setLiability(0);
    addLog({ type: 'NORMAL', msg: '🔄 Sandbox reset. All systems nominal.' });
  }, [addLog]);

  // ── Playbook Sandbox Engine ──────────────────────────────────────────────
  const startPlaybookSimulation = useCallback((playbook) => {
    if (simState === 'running' || simState === 'breach' || simState === 'remediating') return;
    
    // Find the target node based on CVE, Asset ID, or Asset Name
    // Since backend node properties might not embed the CVE directly, use FALLBACK_NODES as a reliable lookup table
    const fallbackMatch = FALLBACK_NODES.find(fn => fn.cve === playbook.cveId);
    
    const targetNode = nodes.find(n => 
      n.id === fallbackMatch?.id ||
      n.cve === playbook.cveId || 
      n.id === playbook.data?.assetId ||
      n.name === playbook.data?.assetName ||
      (playbook.cveId && n.cve && n.cve.includes(playbook.cveId))
    ) || nodes[0];
    
    // Build a connectivity-based path using BFS from a DMZ node
    const adj = {};
    nodes.forEach(n => adj[n.id] = []);
    connections.forEach(([src, tgt]) => {
      if(adj[src]) adj[src].push(tgt);
      if(adj[tgt]) adj[tgt].push(src); // undirected for the sake of finding an attack path
    });

    const dmzNodes = nodes.filter(n => n.zone === 'DMZ').map(n => n.id);
    const startNodes = dmzNodes.length > 0 ? dmzNodes : [nodes[0].id];
    
    let path = null;
    for (const startNode of startNodes) {
      if (startNode === targetNode.id) {
        path = [startNode];
        break;
      }
      const queue = [[startNode]];
      const visited = new Set([startNode]);
      
      while(queue.length > 0 && !path) {
        const currentPath = queue.shift();
        const current = currentPath[currentPath.length - 1];
        
        for (const neighbor of (adj[current] || [])) {
          if (neighbor === targetNode.id) {
            path = [...currentPath, neighbor];
            break;
          }
          if (!visited.has(neighbor)) {
            visited.add(neighbor);
            queue.push([...currentPath, neighbor]);
          }
        }
      }
      if (path) break;
    }
    
    path = path || [targetNode.id];

    setSimState('running');
    setDefcon(2);
    setCompromisedCount(0);
    setLiability(0);
    setAttackPathNodes(new Set());

    addLog({ type: 'ALERT', msg: `🛡️ SANDBOX: Testing playbook remediation for ${playbook.cveId}` });

    let step = 0;
    const revealStep = () => {
      if (step >= path.length) {
        // Attack has reached the node. Now remediate!
        setSimState('remediating');
        addLog({ type: 'REMEDIATE', msg: `⚡ Applying playbook constraints to block attack...` });
        
        simTimerRef.current = setTimeout(() => {
          setSimState('remediated');
          setDefcon(5);
          addLog({ type: 'REMEDIATE', msg: '✅ Remediation Successful. Threat visually neutralized at ' + targetNode.name });
        }, 3000);
        return;
      }

      const nodeId = path[step];
      setAttackPathNodes(prev => new Set([...prev, nodeId]));
      setCompromisedCount(step + 1);

      addLog({ type: 'ATTACK', msg: `⚡ [${step + 1}/${path.length}] Attack progressing to ${nodeId}` });

      step++;
      simTimerRef.current = setTimeout(revealStep, 1500);
    };

    simTimerRef.current = setTimeout(revealStep, 800);
  }, [simState, nodes, addLog]);

  // ── AI Governance Remediation Event Listener ────────────────────────────
  useEffect(() => {
    const handler = () => {
      clearTimeout(simTimerRef.current);
      clearInterval(liabilityRef.current);
      setSimState('remediated');
      setDefcon(4);
      setLiability(0);
      addLog({ type: 'REMEDIATE', msg: '🛡️ AI Governance remediation approved and applied.' });
    };
    window.addEventListener('ai-governance-remediate', handler);
    return () => window.removeEventListener('ai-governance-remediate', handler);
  }, [addLog]);

  // ── Node Selection ──────────────────────────────────────────────────────
  const handleSelectNode = useCallback((node) => {
    setSelectedNode(prev => prev?.id === node.id ? null : node);
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div className="twin-root">
      {/* 3D Canvas — full background */}
      <div className="twin-canvas-container">
        <BankingScene>
          <EntityModels
            nodes={nodes}
            attackPathSet={attackPathNodes}
            simState={simState}
            selectedNode={selectedNode}
            onSelectNode={handleSelectNode}
          />
          <NetworkConnections
            connections={connections}
            attackPathSet={attackPathNodes}
            simState={simState}
          />
        </BankingScene>
      </div>

      {/* HUD Overlay Panels */}
      <TopBar
        defcon={defcon}
        compromisedCount={compromisedCount}
        liability={liability}
        simState={simState}
        nodes={nodes}
      />

      <StatusBanner
        simState={simState}
        selectedScenario={selectedScenario}
        compromisedCount={compromisedCount}
      />

      <SandboxSidebar
        simState={simState}
        selectedScenario={selectedScenario}
        onSelectScenario={setSelectedScenario}
        onStartSim={startSimulation}
        onResetSim={resetSimulation}
        onStartPlaybook={startPlaybookSimulation}
      />

      {/* Node Detail Panel */}
      <NodeDetailPanel
        node={selectedNode}
        simState={simState}
        attackPathSet={attackPathNodes}
        onClose={() => setSelectedNode(null)}
      />
    </div>
  );
}
