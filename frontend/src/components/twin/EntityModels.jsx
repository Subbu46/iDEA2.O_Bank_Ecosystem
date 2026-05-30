// ─────────────────────────────────────────────────────────────────────────────
// twin/EntityModels.jsx
// 12 GLB-loaded 3D models for the banking infrastructure Digital Twin.
// Smart behaviors: threat-state emissive glow, idle breathing, live data sync.
// Falls back to placeholder boxes if a GLB model fails to load.
// ─────────────────────────────────────────────────────────────────────────────
import React, { useRef, useState, useMemo, Suspense } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html, useGLTF } from '@react-three/drei';
import * as THREE from 'three';
import { NODE_POSITIONS, ENTITY_VISUALS, GLB_MODELS, STATE_COLORS, getThreatState } from './twinData';

// ── Preload all GLB models in parallel ──────────────────────────────────────
try {
  Object.values(GLB_MODELS).forEach(config => {
    useGLTF.preload(config.url);
  });
} catch (_) { /* preload is best-effort */ }

// ── Error Boundary for individual GLB loads ─────────────────────────────────
class ModelErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error) {
    console.warn('[EntityModels] GLB load error:', error?.message || error);
  }
  render() {
    if (this.state.hasError) return this.props.fallback || null;
    return this.props.children;
  }
}

// ── Base Platform (status ring under each entity) ───────────────────────────
function BasePlatform({ width, state }) {
  const sc = STATE_COLORS[state] || STATE_COLORS.secure;
  const ringRef = useRef();

  useFrame(({ clock }) => {
    if (ringRef.current && (state === 'compromised' || state === 'attacking' || state === 'critical')) {
      const s = 1 + Math.sin(clock.getElapsedTime() * 3) * 0.08;
      ringRef.current.scale.set(s, 1, s);
      ringRef.current.material.opacity = 0.3 + Math.sin(clock.getElapsedTime() * 4) * 0.2;
    }
  });

  return (
    <group>
      {/* Platform disc */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.05, 0]}>
        <circleGeometry args={[width * 0.7, 32]} />
        <meshStandardMaterial color="#d1d5db" roughness={0.5} metalness={0.2} />
      </mesh>

      {/* Status ring */}
      <mesh ref={ringRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.08, 0]}>
        <ringGeometry args={[width * 0.65, width * 0.72, 48]} />
        <meshStandardMaterial
          color={sc.color}
          transparent
          opacity={0.5}
          emissive={sc.color}
          emissiveIntensity={0.5}
          side={THREE.DoubleSide}
        />
      </mesh>
    </group>
  );
}

// ── GLB Model Renderer ──────────────────────────────────────────────────────
// Loads a .glb file, clones the scene with independent materials so that
// per-entity emissive modifications don't bleed across instances.
function GLBModel({ url, modelScale, modelRotation, yOffset, state }) {
  const { scene } = useGLTF(url);

  // Deep-clone the scene + materials so each entity is independent
  const clonedScene = useMemo(() => {
    const clone = scene.clone();
    clone.traverse(child => {
      if (child.isMesh) {
        child.material = child.material.clone();
        child.castShadow = true;
        child.receiveShadow = true;
      }
    });
    return clone;
  }, [scene]);

  useFrame(({ clock }) => {
    if (!clonedScene) return;
    const isThreated = state === 'compromised' || state === 'critical' || state === 'attacking';
    const isRemediating = state === 'remediating';
    const isRemediated = state === 'remediated';

    clonedScene.traverse(child => {
      if (child.isMesh && child.material) {
        if (isThreated) {
          const color = state === 'compromised' ? 0xef4444 :
            state === 'critical' ? 0xdc2626 : 0xf97316;
          child.material.emissive.setHex(color);
          child.material.emissiveIntensity = 0.4 + Math.sin(clock.getElapsedTime() * 4) * 0.3;
        } else if (isRemediating) {
          child.material.emissive.setHex(0x0ea5e9); // Cyan pulse
          child.material.emissiveIntensity = 0.5 + Math.sin(clock.getElapsedTime() * 8) * 0.4;
        } else if (isRemediated) {
          child.material.emissive.setHex(0x10b981); // Solid green shield
          child.material.emissiveIntensity = 0.4;
        } else if (state === 'vulnerable') {
          child.material.emissive.setHex(0xd97706);
          child.material.emissiveIntensity = 0.15;
        } else {
          child.material.emissiveIntensity = 0;
        }
      }
    });
  });

  const scale = typeof modelScale === 'number'
    ? [modelScale, modelScale, modelScale]
    : modelScale;

  return (
    <primitive
      object={clonedScene}
      scale={scale}
      rotation={modelRotation || [0, 0, 0]}
      position={[0, yOffset || 0, 0]}
    />
  );
}

// ── Fallback Box (rendered while GLB loads or on error) ─────────────────────
function FallbackBox({ visual }) {
  const meshRef = useRef();

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.material.opacity = 0.4 + Math.sin(clock.getElapsedTime() * 2) * 0.15;
    }
  });

  return (
    <group>
      <mesh ref={meshRef} position={[0, visual.height / 2, 0]} castShadow>
        <boxGeometry args={[visual.width, visual.height, visual.width]} />
        <meshStandardMaterial
          color={visual.color}
          roughness={0.4}
          metalness={0.3}
          transparent
          opacity={0.5}
          wireframe
        />
      </mesh>
      {/* Loading indicator ring */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.15, 0]}>
        <ringGeometry args={[visual.width * 0.45, visual.width * 0.52, 32]} />
        <meshStandardMaterial
          color="#60a5fa"
          emissive="#3b82f6"
          emissiveIntensity={0.5}
          transparent
          opacity={0.6}
          side={THREE.DoubleSide}
        />
      </mesh>
    </group>
  );
}

// ── Single Entity (GLB Model + Platform + Label + Selection Ring) ────────────
function Entity({ node, visual, position, state, selected, onSelect, glbConfig }) {
  const groupRef = useRef();
  const innerRef = useRef();
  const [hovered, setHovered] = useState(false);
  const sc = STATE_COLORS[state] || STATE_COLORS.secure;
  // Random offset so entities don't breathe in sync
  const idleOffset = useMemo(() => Math.random() * Math.PI * 2, []);

  useFrame(({ clock }) => {
    // Hover / select scale lerp
    if (groupRef.current) {
      const targetScale = hovered || selected ? 1.08 : 1;
      groupRef.current.scale.lerp(
        new THREE.Vector3(targetScale, targetScale, targetScale),
        0.1
      );
    }
    // Idle breathing — subtle Y oscillation to make the scene feel alive
    if (innerRef.current) {
      innerRef.current.position.y = Math.sin(clock.getElapsedTime() * 0.7 + idleOffset) * 0.06;
    }
  });

  const labelHeight = (glbConfig?.labelHeight || visual.height) + 2.2;

  return (
    <group
      ref={groupRef}
      position={position}
      onPointerOver={(e) => { e.stopPropagation(); setHovered(true); document.body.style.cursor = 'pointer'; }}
      onPointerOut={() => { setHovered(false); document.body.style.cursor = 'default'; }}
      onClick={(e) => { e.stopPropagation(); onSelect(node); }}
    >
      <group ref={innerRef}>
        <BasePlatform width={visual.width} state={state} />

        {/* 3D Model — GLB with Suspense + ErrorBoundary fallback */}
        <ModelErrorBoundary fallback={<FallbackBox visual={visual} />}>
          <Suspense fallback={<FallbackBox visual={visual} />}>
            {glbConfig ? (
              <GLBModel
                url={glbConfig.url}
                modelScale={glbConfig.scale}
                modelRotation={glbConfig.rotation}
                yOffset={glbConfig.yOffset}
                state={state}
              />
            ) : (
              <FallbackBox visual={visual} />
            )}
          </Suspense>
        </ModelErrorBoundary>

        {/* Floating HTML label above the entity */}
        <Html
          position={[0, labelHeight, 0]}
          center
          occlude={false}
          distanceFactor={30}
          style={{ pointerEvents: 'none' }}
        >
          <div className="twin-3d-label">
            <div className="name">{visual.label}</div>
            <div className="ip">{node.ip}</div>
            <div
              className="status-badge"
              style={{
                background: `${sc.color}18`,
                color: sc.color,
                border: `1px solid ${sc.color}40`,
              }}
            >
              <span style={{
                width: 5, height: 5, borderRadius: '50%',
                background: sc.color, display: 'inline-block',
                boxShadow: `0 0 4px ${sc.color}`,
              }} />
              {sc.label}
            </div>
          </div>
        </Html>

        {/* Selection highlight ring */}
        {selected && (
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.12, 0]}>
            <ringGeometry args={[visual.width * 0.8, visual.width * 0.9, 48]} />
            <meshStandardMaterial
              color="#3b82f6"
              emissive="#3b82f6"
              emissiveIntensity={0.6}
              transparent
              opacity={0.7}
              side={THREE.DoubleSide}
            />
          </mesh>
        )}
      </group>
    </group>
  );
}

// ── All Entities ────────────────────────────────────────────────────────────
export default function EntityModels({ nodes, attackPathSet, simState, selectedNode, onSelectNode }) {
  return (
    <group>
      {nodes.map(node => {
        const pos = NODE_POSITIONS[node.id];
        const visual = ENTITY_VISUALS[node.id];
        const glbConfig = GLB_MODELS[node.id];
        if (!pos || !visual) return null;

        const state = getThreatState(node, attackPathSet, simState);

        return (
          <Entity
            key={node.id}
            node={node}
            visual={visual}
            position={pos}
            state={state}
            selected={selectedNode?.id === node.id}
            onSelect={onSelectNode}
            glbConfig={glbConfig}
          />
        );
      })}
    </group>
  );
}
