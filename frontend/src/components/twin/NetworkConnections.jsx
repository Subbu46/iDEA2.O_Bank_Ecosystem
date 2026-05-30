// ─────────────────────────────────────────────────────────────────────────────
// twin/NetworkConnections.jsx
// Animated 3D network cables between banking infrastructure entities.
// Normal state: subtle dark tubes with traveling data particles.
// Attack state: red pulsing tubes with rapid particle flow + glow.
// ─────────────────────────────────────────────────────────────────────────────
import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { NODE_POSITIONS } from './twinData';

// ── Catenary Curve Generator ────────────────────────────────────────────────
function createCatenaryPoints(start, end, segments = 32, sag = 0.15) {
  const points = [];
  const dx = end[0] - start[0];
  const dy = end[1] - start[1];
  const dz = end[2] - start[2];
  const dist = Math.sqrt(dx * dx + dz * dz);
  const sagAmount = dist * sag;

  for (let i = 0; i <= segments; i++) {
    const t = i / segments;
    const x = start[0] + dx * t;
    const baseY = start[1] + dy * t;
    // Parabolic arch curving upwards
    const sagY = 4 * sagAmount * t * (1 - t);
    const y = baseY + sagY + 1.5; // Elevate cables above ground
    const z = start[2] + dz * t;
    points.push(new THREE.Vector3(x, y, z));
  }
  return points;
}

// ── Data Flow Particles ─────────────────────────────────────────────────────
function DataParticles({ curve, isAttack, speed = 1 }) {
  const count = isAttack ? 6 : 3;
  const refs = useRef([]);

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    refs.current.forEach((mesh, i) => {
      if (!mesh) return;
      const offset = i / count;
      const progress = ((t * speed * (isAttack ? 2.5 : 0.8)) + offset) % 1;
      const point = curve.getPointAt(progress);
      mesh.position.copy(point);
    });
  });

  return (
    <>
      {[...Array(count)].map((_, i) => (
        <mesh key={i} ref={el => (refs.current[i] = el)}>
          <sphereGeometry args={[isAttack ? 0.3 : 0.22, 16, 16]} />
          <meshStandardMaterial
            color={isAttack ? '#ef4444' : '#00d2ff'}
            emissive={isAttack ? '#ef4444' : '#0099ff'}
            emissiveIntensity={isAttack ? 2.5 : 4.0}
            toneMapped={false}
            transparent
            opacity={0.95}
          />
        </mesh>
      ))}
    </>
  );
}

// ── Single Connection Cable ─────────────────────────────────────────────────
function ConnectionCable({ srcPos, dstPos, isAttackEdge, simState }) {
  const tubeRef = useRef();
  const isActive = isAttackEdge && (simState === 'running' || simState === 'breach');

  const { curve, tubeGeom } = useMemo(() => {
    const pts = createCatenaryPoints(srcPos, dstPos, 32, 0.12);
    const c = new THREE.CatmullRomCurve3(pts);
    const g = new THREE.TubeGeometry(c, 32, isActive ? 0.06 : 0.035, 8, false);
    return { curve: c, tubeGeom: g };
  }, [srcPos, dstPos, isActive]);

  useFrame(({ clock }) => {
    if (tubeRef.current && isActive) {
      const pulse = 0.7 + Math.sin(clock.getElapsedTime() * 5) * 0.3;
      tubeRef.current.material.opacity = pulse;
      tubeRef.current.material.emissiveIntensity = 0.5 + Math.sin(clock.getElapsedTime() * 6) * 0.5;
    }
  });

  return (
    <group>
      {/* Main cable tube */}
      <mesh ref={tubeRef} geometry={tubeGeom}>
        <meshStandardMaterial
          color={isActive ? '#ef4444' : '#000000'}
          emissive={isActive ? '#dc2626' : '#000000'}
          emissiveIntensity={isActive ? 0.5 : 0.0}
          transparent={true}
          opacity={isActive ? 0.85 : 0.95}
          roughness={0.3}
          metalness={0.8}
        />
      </mesh>

      {/* Outer glow tube for attack state */}
      {isActive && (
        <mesh geometry={new THREE.TubeGeometry(curve, 32, 0.12, 8, false)}>
          <meshStandardMaterial
            color="#ef4444"
            emissive="#ef4444"
            emissiveIntensity={0.3}
            transparent
            opacity={0.15}
            side={THREE.DoubleSide}
          />
        </mesh>
      )}

      {/* Traveling data particles */}
      <DataParticles curve={curve} isAttack={isActive} />
    </group>
  );
}

// ── All Network Connections ─────────────────────────────────────────────────
export default function NetworkConnections({ connections, attackPathSet, simState }) {
  return (
    <group>
      {connections.map(([srcId, dstId], idx) => {
        const srcPos = NODE_POSITIONS[srcId];
        const dstPos = NODE_POSITIONS[dstId];
        if (!srcPos || !dstPos) return null;

        const isAttackEdge = attackPathSet &&
          attackPathSet.has(srcId) && attackPathSet.has(dstId);

        return (
          <ConnectionCable
            key={`${srcId}-${dstId}-${idx}`}
            srcPos={srcPos}
            dstPos={dstPos}
            isAttackEdge={isAttackEdge}
            simState={simState}
          />
        );
      })}
    </group>
  );
}
