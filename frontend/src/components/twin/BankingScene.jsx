// ─────────────────────────────────────────────────────────────────────────────
// twin/BankingScene.jsx
// Three.js Canvas — Enterprise cyber-infrastructure floor, ambient lighting,
// orbit camera controls, PBR environment for GLB models.
// Updated zone markers match the U-curve wavy node layout.
// ─────────────────────────────────────────────────────────────────────────────
import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Html, Grid, Environment } from '@react-three/drei';
import * as THREE from 'three';
import { ZONES, ZONE_MAP, NODE_POSITIONS } from './twinData';

// ── Corporate Floor Grid ────────────────────────────────────────────────────
function CorporateFloor() {
  return (
    <group>
      {/* Main floor plane — polished dark surface */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.05, 0]} receiveShadow>
        <planeGeometry args={[120, 120]} />
        <meshStandardMaterial
          color="#e8ecf1"
          roughness={0.3}
          metalness={0.1}
        />
      </mesh>

      {/* Grid overlay — subtle blueprint-style lines */}
      <Grid
        position={[0, 0.01, 0]}
        args={[120, 120]}
        cellSize={2}
        cellThickness={0.5}
        cellColor="#c8d3e0"
        sectionSize={10}
        sectionThickness={1}
        sectionColor="#94a8c0"
        fadeDistance={80}
        fadeStrength={1.2}
        followCamera={false}
        infiniteGrid={false}
      />
    </group>
  );
}

// ── Zone Floor Markers (updated for U-curve wavy layout) ────────────────────
// Each zone's floor strip is wider in the Z-axis to cover the U-curve extents.
function ZoneMarkers() {
  // Zone center Z positions — average of the U-curve row
  // Row extents are wider than flat layout due to the ±5 curve amplitude.
  const zonePositions = {
    'DMZ': { x: 0, z: 23, label: 'ZONE 1 — INTERNET DMZ', zSpan: 16 },
    'Middleware': { x: 0, z: 6, label: 'ZONE 2 — MIDDLEWARE', zSpan: 16 },
    'Core': { x: 0, z: -10, label: 'ZONE 3 — CORE BANKING', zSpan: 16 },
    'Management': { x: 0, z: -26, label: 'ZONE 4 — MANAGEMENT', zSpan: 16 },
  };

  return (
    <group>
      {ZONES.map(zone => {
        const pos = zonePositions[zone.id];
        if (!pos) return null;
        const halfSpan = pos.zSpan / 2;
        return (
          <group key={zone.id}>
            {/* Zone floor highlight strip */}
            <mesh
              rotation={[-Math.PI / 2, 0, 0]}
              position={[pos.x, 0.02, pos.z]}
            >
              <planeGeometry args={[52, pos.zSpan]} />
              <meshStandardMaterial
                color={zone.color}
                transparent
                opacity={0.04}
                roughness={0.9}
              />
            </mesh>

            {/* Zone boundary lines — top and bottom edges */}
            <mesh rotation={[-Math.PI / 2, 0, 0]} position={[pos.x, 0.03, pos.z + halfSpan]}>
              <planeGeometry args={[52, 0.08]} />
              <meshStandardMaterial color={zone.color} transparent opacity={0.35} />
            </mesh>
            <mesh rotation={[-Math.PI / 2, 0, 0]} position={[pos.x, 0.03, pos.z - halfSpan]}>
              <planeGeometry args={[52, 0.08]} />
              <meshStandardMaterial color={zone.color} transparent opacity={0.35} />
            </mesh>

            {/* Zone label */}
            <Html
              position={[-26, 0.2, pos.z]}
              transform
              rotation={[-Math.PI / 2, 0, 0]}
              occlude={false}
              style={{ pointerEvents: 'none' }}
            >
              <div className="twin-zone-label" style={{ color: zone.color }}>
                {pos.label}
              </div>
            </Html>
          </group>
        );
      })}
    </group>
  );
}

// ── Ambient Particles (subtle floating data dots) ────────────────────────────
function AmbientParticles({ count = 200 }) {
  const ref = useRef();
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 80;
      arr[i * 3 + 1] = Math.random() * 15 + 1;
      arr[i * 3 + 2] = (Math.random() - 0.5) * 80;
    }
    return arr;
  }, [count]);

  useFrame((_, delta) => {
    if (ref.current) {
      const posArr = ref.current.geometry.attributes.position.array;
      for (let i = 0; i < count; i++) {
        posArr[i * 3 + 1] += delta * 0.3;
        if (posArr[i * 3 + 1] > 16) posArr[i * 3 + 1] = 1;
      }
      ref.current.geometry.attributes.position.needsUpdate = true;
    }
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={positions}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.08}
        color="#93c5fd"
        transparent
        opacity={0.4}
        sizeAttenuation
      />
    </points>
  );
}

// ── Main Scene Component ────────────────────────────────────────────────────
export default function BankingScene({ children }) {
  return (
    <Canvas
      shadows
      camera={{
        position: [0, 35, 50],
        fov: 50,
        near: 0.1,
        far: 500,
      }}
      gl={{ antialias: true, alpha: false }}
      style={{ background: 'linear-gradient(180deg, #e0e8f0 0%, #cbd5e1 40%, #d4dce8 100%)' }}
    >
      {/* Sky-like gradient background */}
      <color attach="background" args={['#dde4ed']} />
      <fog attach="fog" args={['#dde4ed', 60, 130]} />

      {/* PBR Environment for realistic GLB model reflections */}
      <Environment preset="city" />

      {/* Lighting — clean enterprise daylight */}
      <ambientLight intensity={0.7} color="#f0f4f8" />
      <directionalLight
        position={[30, 40, 20]}
        intensity={1.2}
        color="#ffffff"
        castShadow
        shadow-mapSize-width={2048}
        shadow-mapSize-height={2048}
        shadow-camera-far={120}
        shadow-camera-left={-60}
        shadow-camera-right={60}
        shadow-camera-top={60}
        shadow-camera-bottom={-60}
      />
      <directionalLight position={[-20, 25, -15]} intensity={0.3} color="#bfdbfe" />
      <hemisphereLight args={['#dbeafe', '#e2e8f0', 0.4]} />

      {/* Camera controls — orbit + zoom only */}
      <OrbitControls
        enablePan
        enableZoom
        enableRotate
        maxPolarAngle={Math.PI / 2.3}
        minPolarAngle={Math.PI / 6}
        minDistance={15}
        maxDistance={90}
        dampingFactor={0.08}
        enableDamping
        target={[0, 0, -2]}
      />

      {/* Environment elements */}
      <CorporateFloor />
      <ZoneMarkers />
      <AmbientParticles />

      {/* Scene children (entities, connections, etc.) */}
      {children}
    </Canvas>
  );
}
