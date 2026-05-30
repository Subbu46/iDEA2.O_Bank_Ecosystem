import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Radar,
  ShieldAlert,
  GitFork,
  Lock,
  Database,
  Cpu,
  ShieldCheck,
  Play,
  Pause,
  RotateCcw,
  Trash2,
  Terminal,
  Timer,
  Activity
} from 'lucide-react';

// Static event data representing forensic timeline sequence
const REPLAY_EVENTS = [
  {
    id: 1,
    time: '13:40:01',
    text: 'Reconnaissance Detected',
    severity: 'WARNING',
    icon: Radar,
    color: '#eab308', // Yellow
    desc: 'Port scan & asset enumeration targeting Web Gateway from external subnet.',
    relativeDelay: 0
  },
  {
    id: 2,
    time: '13:40:05',
    text: 'Credential Stuffing Attempt',
    severity: 'ATTACK',
    icon: ShieldAlert,
    color: '#ef4444', // Red
    desc: 'High-frequency brute-force login attempts detected on active auth endpoints.',
    relativeDelay: 1300
  },
  {
    id: 3,
    time: '13:40:12',
    text: 'Lateral Movement Initiated',
    severity: 'ATTACK',
    icon: GitFork,
    color: '#ef4444', // Red
    desc: 'Pivot action from Web Gateway towards internal IAM Authentication Router.',
    relativeDelay: 1300
  },
  {
    id: 4,
    time: '13:40:19',
    text: 'IAM Compromise',
    severity: 'ATTACK',
    icon: Lock,
    color: '#ef4444', // Red
    desc: 'Privilege escalation triggered via manipulated session credentials.',
    relativeDelay: 1300
  },
  {
    id: 5,
    time: '13:40:26',
    text: 'Database Access Attempt',
    severity: 'ATTACK',
    icon: Database,
    color: '#ef4444', // Red
    desc: 'Unauthorized query execution targeting Core Financial Ledger DB.',
    relativeDelay: 1300
  },
  {
    id: 6,
    time: '13:40:30',
    text: 'AI Remediation Triggered',
    severity: 'INFO',
    icon: Cpu,
    color: '#3b82f6', // Blue
    desc: 'Automated defense policies activated to isolate database network interfaces.',
    relativeDelay: 1600
  },
  {
    id: 7,
    time: '13:40:33',
    text: 'Threat Contained',
    severity: 'SUCCESS',
    icon: ShieldCheck,
    color: '#22c55e', // Green
    desc: 'Attack path blocked completely. Credentials revoked. Session terminated.',
    relativeDelay: 1400
  }
];

// Helper Typewriter component for realistic cinematic printing effect
function Typewriter({ text, speed = 25, onComplete }) {
  const [displayText, setDisplayText] = useState('');

  useEffect(() => {
    let index = 0;
    setDisplayText('');

    const timer = setInterval(() => {
      if (index < text.length) {
        setDisplayText(prev => prev + text.charAt(index));
        index++;
      } else {
        clearInterval(timer);
        if (onComplete) onComplete();
      }
    }, speed);

    return () => clearInterval(timer);
  }, [text, speed, onComplete]);

  return <span>{displayText}</span>;
}

export default function AttackReplayTimeline({ simState, onReset }) {
  const [visibleCount, setVisibleCount] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(0);

  const scrollContainerRef = useRef(null);
  const timerIntervalRef = useRef(null);
  const nextEventTimeoutRef = useRef(null);
  const startTimeRef = useRef(null);
  const pausedTimeRef = useRef(null);

  // Sync with main simulation triggers
  useEffect(() => {
    if (simState === 'running') {
      startReplay();
    } else if (simState === 'idle') {
      resetReplayState();
    }
  }, [simState]);

  // Clean up all timers and schedules on unmount
  useEffect(() => {
    return () => {
      clearAllTimers();
    };
  }, []);

  // Scroll to bottom helper when visible count changes
  useEffect(() => {
    if (scrollContainerRef.current) {
      setTimeout(() => {
        scrollContainerRef.current.scrollTo({
          top: scrollContainerRef.current.scrollHeight,
          behavior: 'smooth'
        });
      }, 100);
    }
  }, [visibleCount]);

  const clearAllTimers = () => {
    if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
    if (nextEventTimeoutRef.current) clearTimeout(nextEventTimeoutRef.current);
  };

  const startReplay = () => {
    clearAllTimers();
    setVisibleCount(1);
    setIsPlaying(true);
    setIsPaused(false);
    setElapsedTime(0);

    startTimeRef.current = Date.now();
    pausedTimeRef.current = null;

    // Milliseconds stopwatch timer
    timerIntervalRef.current = setInterval(() => {
      if (startTimeRef.current) {
        setElapsedTime(Date.now() - startTimeRef.current);
      }
    }, 37);

    // Schedule the next step in the forensic replay
    scheduleNextEvent(2);
  };

  const scheduleNextEvent = (nextId) => {
    if (nextId > REPLAY_EVENTS.length) {
      // Completed replay
      setIsPlaying(false);
      clearAllTimers();
      return;
    }

    const nextEvent = REPLAY_EVENTS.find(e => e.id === nextId);
    if (!nextEvent) return;

    nextEventTimeoutRef.current = setTimeout(() => {
      setVisibleCount(nextId);
      scheduleNextEvent(nextId + 1);
    }, nextEvent.relativeDelay);
  };

  const handlePauseToggle = () => {
    if (!isPlaying && visibleCount === 0) return;

    if (isPaused) {
      // Resume playback
      setIsPaused(false);

      // Adjust start time for stopwatch offset
      const pausedDuration = Date.now() - pausedTimeRef.current;
      startTimeRef.current += pausedDuration;

      timerIntervalRef.current = setInterval(() => {
        setElapsedTime(Date.now() - startTimeRef.current);
      }, 37);

      // Re-schedule upcoming step
      if (visibleCount < REPLAY_EVENTS.length) {
        const nextId = visibleCount + 1;
        const nextEvent = REPLAY_EVENTS.find(e => e.id === nextId);
        nextEventTimeoutRef.current = setTimeout(() => {
          setVisibleCount(nextId);
          scheduleNextEvent(nextId + 1);
        }, nextEvent.relativeDelay);
      }
    } else {
      // Pause playback
      setIsPaused(true);
      pausedTimeRef.current = Date.now();
      clearAllTimers();
    }
  };

  const handleClearReplay = () => {
    clearAllTimers();
    setVisibleCount(0);
    setIsPlaying(false);
    setIsPaused(false);
    setElapsedTime(0);
  };

  const resetReplayState = () => {
    clearAllTimers();
    setVisibleCount(0);
    setIsPlaying(false);
    setIsPaused(false);
    setElapsedTime(0);
  };

  // Replay from beginning (Local Trigger)
  const handleReplayAgain = () => {
    // If the simulation is idle, let's trigger it in the parent
    if (simState === 'idle' && onReset) {
      onReset();
    }
    startReplay();
  };

  const progressPercent = REPLAY_EVENTS.length > 0
    ? (visibleCount / REPLAY_EVENTS.length) * 100
    : 0;

  const secondsFormatted = (elapsedTime / 1000).toFixed(2) + 's';

  // Define active events list based on count
  const activeEvents = REPLAY_EVENTS.slice(0, visibleCount);

  return (
    <div
      className="attack-replay-panel"
      style={{
        position: 'relative',
        width: '100%',
        height: '340px',
        maxHeight: '340px',
        background: 'rgba(7, 10, 22, 0.85)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(59, 130, 246, 0.25)',
        boxShadow: '0 16px 48px rgba(0, 0, 0, 0.75), inset 0 0 20px rgba(59, 130, 246, 0.05)',
        borderRadius: '12px',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 10,
        fontFamily: "'JetBrains Mono', monospace",
        overflow: 'hidden',
        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
        marginTop: '16px',
        marginBottom: '16px'
      }}
    >
      {/* Header Info */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '14px 18px',
          borderBottom: '1px solid rgba(59, 130, 246, 0.15)',
          background: 'rgba(59, 130, 246, 0.08)',
          userSelect: 'none',
          position: 'relative',
          zIndex: 1,
          overflow: 'visible'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Terminal size={16} className="text-blue-600 dark:text-blue-400" />
          <span style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '1.5px', color: '#fff' }}>
            FORENSIC ATTACK REPLAY
          </span>
        </div>

        {/* Blinking Live indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: isPaused ? '#eab308' : (isPlaying ? '#ef4444' : '#64748b'),
              boxShadow: isPaused
                ? '0 0 10px #eab308'
                : (isPlaying ? '0 0 10px #ef4444' : 'none'),
              animation: isPaused || !isPlaying ? 'none' : 'replay-blink 1s infinite alternate'
            }}
          />
          <span style={{ fontSize: '15px', fontWeight: 800, color: isPaused ? '#eab308' : (isPlaying ? '#ef4444' : '#64748b'), letterSpacing: '1px' }}>
            {isPaused ? 'PAUSED' : (isPlaying ? 'LIVE' : 'STANDBY')}
          </span>
        </div>
      </div>

      {/* Embedded specific blink animation */}
      <style>{`
        @keyframes replay-blink {
          0% { opacity: 0.2; }
          100% { opacity: 1; }
        }
      `}</style>

      {/* Progress & Duration Section */}
      <div
        style={{
          padding: '12px 18px 10px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '16px',
          color: '#e2e8f0',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          background: 'rgba(0, 0, 0, 0.35)',
          userSelect: 'none',
          position: 'relative',
          zIndex: 1,
          overflow: 'visible'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Timer size={14} className="text-slate-500 dark:text-slate-600 dark:text-slate-400" />
          <span>TIME: <span style={{ color: '#60a5fa', fontWeight: 'bold' }}>{secondsFormatted}</span></span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span>STEP: <span style={{ color: '#fff', fontWeight: 'bold' }}>{visibleCount}</span>/7</span>
        </div>
      </div>

      {/* Replay Progress Bar */}
      <div style={{ height: '4px', width: '100%', background: 'rgba(255,255,255,0.05)', position: 'relative', overflow: 'visible', zIndex: 1 }}>
        <div
          style={{
            height: '100%',
            width: `${progressPercent}%`,
            background: 'linear-gradient(90deg, #3b82f6, #60a5fa)',
            boxShadow: '0 0 8px #60a5fa',
            transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1)'
          }}
        />
      </div>

      {/* Timeline Events Scroll Area */}
      <div
        ref={scrollContainerRef}
        className="log-scroll"
        style={{
          flex: 1,
          overflowY: 'auto',
          minHeight: 0,
          marginTop: '12px',
          paddingTop: '12px',
          paddingLeft: '20px',
          paddingRight: '10px',
          paddingBottom: '18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          position: 'relative',
          zIndex: 2,
          overflowX: 'hidden'
        }}
      >
        {activeEvents.length === 0 ? (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              height: '100%',
              color: '#94a3b8',
              fontSize: '15px',
              textAlign: 'center',
              lineHeight: 1.6,
              padding: '0 20px'
            }}
          >
            <Activity size={28} style={{ color: '#334155', marginBottom: '10px' }} />
            <span style={{ fontWeight: 700, letterSpacing: '0.5px' }}>[NO ACTIVE THREAT STREAM PLAYBACK]</span>
            <span style={{ fontSize: '15px', color: '#475569', marginTop: '6px' }}>
              Click 'SIMULATE ATTACK' on the right panel to trigger cinematic live replay logs.
            </span>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {activeEvents.map((evt, idx) => {
              const EventIcon = evt.icon;
              const isLatest = idx === activeEvents.length - 1;
              return (
                <motion.div
                  key={evt.id}
                  initial={{ opacity: 0, x: -15, y: 5 }}
                  animate={{
                    opacity: 1,
                    x: 0,
                    y: 0,
                    boxShadow: isLatest ? `0 0 12px rgba(${evt.severity === 'ATTACK' ? '239, 68, 68' : (evt.severity === 'SUCCESS' ? '34, 197, 150' : '234, 179, 8')}, 0.15)` : 'none'
                  }}
                  transition={{ duration: 0.35, ease: 'easeOut' }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '16px',
                    minHeight: '110px',
                    padding: '18px 20px',
                    borderRadius: '8px',
                    background: isLatest ? 'rgba(30, 41, 59, 0.65)' : 'rgba(15, 23, 42, 0.45)',
                    border: isLatest ? `1px solid ${evt.color}66` : '1px solid rgba(255, 255, 255, 0.08)',
                    position: 'relative',
                    overflow: 'hidden',
                    marginTop: idx === 0 ? '8px' : '0',
                    zIndex: 10
                  }}
                >
                  {/* Left accent color bar */}
                  <div
                    style={{
                      position: 'absolute',
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: '3px',
                      backgroundColor: evt.color
                    }}
                  />

                  {/* Severity Icon Indicator */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '32px',
                      height: '32px',
                      borderRadius: '6px',
                      background: `${evt.color}20`,
                      border: `1px solid ${evt.color}50`,
                      color: evt.color,
                      flexShrink: 0
                    }}
                  >
                    <EventIcon size={18} className={isLatest && evt.severity === 'ATTACK' ? 'animate-pulse' : ''} />
                  </div>

                  {/* Text Details */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px', gap: '10px' }}>
                      <span style={{ fontSize: '15px', color: '#94a3b8', fontWeight: 700 }}>
                        [{evt.time}]
                      </span>
                      <span
                        style={{
                          fontSize: '14px',
                          fontWeight: 900,
                          padding: '5px 14px',
                          borderRadius: '4px',
                          background: `${evt.color}25`,
                          color: evt.color,
                          border: `1px solid ${evt.color}40`,
                          whiteSpace: 'nowrap',
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center'
                        }}
                      >
                        {evt.severity}
                      </span>
                    </div>

                    <div style={{ fontSize: '16px', fontWeight: 800, color: isLatest ? '#fff' : '#f1f5f9', letterSpacing: '0.25px', lineHeight: 1.4 }}>
                      {isLatest ? (
                        <Typewriter text={evt.text} speed={25} />
                      ) : (
                        <span>{evt.text}</span>
                      )}
                    </div>

                    <div style={{ fontSize: '15px', color: '#94a3b8', marginTop: '6px', lineHeight: 1.45 }}>
                      {evt.desc}
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
      </div>

      {/* Footer Interactive Controllers */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 18px',
          borderTop: '1px solid rgba(59, 130, 246, 0.2)',
          background: 'rgba(7, 10, 22, 0.98)',
          gap: '10px',
          userSelect: 'none',
          flexShrink: 0
        }}
      >
        <button
          onClick={handlePauseToggle}
          disabled={visibleCount === 0}
          title={isPaused ? "Resume Playback" : "Pause Playback"}
          style={{
            flex: 1.2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            padding: '10px 0',
            borderRadius: '6px',
            background: isPaused ? 'rgba(59, 130, 246, 0.2)' : 'rgba(255, 255, 255, 0.08)',
            border: isPaused ? '1px solid rgba(59, 130, 246, 0.5)' : '1px solid rgba(255,255,255,0.15)',
            color: visibleCount === 0 ? '#475569' : (isPaused ? '#60a5fa' : '#e2e8f0'),
            cursor: visibleCount === 0 ? 'not-allowed' : 'pointer',
            fontSize: '16px',
            fontWeight: 800,
            transition: 'all 0.2s'
          }}
        >
          {isPaused ? <Play size={12} /> : <Pause size={12} />}
          <span>{isPaused ? 'RESUME' : 'PAUSE'}</span>
        </button>

        <button
          onClick={handleReplayAgain}
          title="Replay from Beginning"
          style={{
            flex: 1.2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            padding: '8px 0',
            borderRadius: '6px',
            background: 'rgba(255, 255, 255, 0.08)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            color: '#e2e8f0',
            cursor: 'pointer',
            fontSize: '16px',
            fontWeight: 800,
            transition: 'all 0.2s'
          }}
        >
          <RotateCcw size={12} />
          <span>REPLAY</span>
        </button>

        <button
          onClick={handleClearReplay}
          disabled={visibleCount === 0}
          title="Clear Forensic Terminal"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '8px 16px',
            borderRadius: '6px',
            background: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            color: visibleCount === 0 ? '#475569' : '#fca5a5',
            cursor: visibleCount === 0 ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s'
          }}
        >
          <Trash2 size={14} />
        </button>
      </div>
    </div>
  );
}
