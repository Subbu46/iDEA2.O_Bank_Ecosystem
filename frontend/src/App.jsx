import React, { useState, useEffect, useRef } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Home, Network, Bell, BookOpen, ShieldAlert, Cpu, ChevronLeft, ChevronRight, Menu } from 'lucide-react';
import Dashboard from './components/Dashboard';
import KnowledgeGraph from './components/KnowledgeGraph';
import PlaybookViewer from './components/PlaybookViewer';
import RedTeamSim from './components/RedTeamSim';
import DigitalTwin from './components/DigitalTwin';
import client, { alertsApi } from './api/client';

function AppContent() {
  const location = useLocation();
  const navigate = useNavigate();
  const isTwin = location.pathname === '/twin';

  const [notifications, setNotifications] = useState([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const dropdownRef = useRef(null);

  // Poll alerts every 10 seconds and merge with custom notifications
  const fetchAlerts = () => {
    alertsApi.listAlerts()
      .then((data) => {
        if (!data || !Array.isArray(data)) return;

        const alertNotifications = data.map(alert => ({
          id: alert.id,
          type: 'alert',
          severity: alert.severity,
          message: alert.message,
          timestamp: alert.timestamp,
          status: alert.status,
          cveId: alert.cve_id,
          assetId: alert.asset_id
        }));

        setNotifications(prev => {
          const customs = prev.filter(n => n.type === 'custom');
          const merged = [...customs];
          alertNotifications.forEach(an => {
            const existingIdx = merged.findIndex(m => m.id === an.id);
            if (existingIdx === -1) {
              merged.push(an);
            } else {
              merged[existingIdx] = { ...merged[existingIdx], status: an.status };
            }
          });
          return merged.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        });
      })
      .catch(err => console.error("Failed to load alerts for header notifications:", err));
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  // Listen to custom window notifications (e.g. from Dashboard)
  useEffect(() => {
    const handleAddNotif = (e) => {
      const newNotif = e.detail;
      setNotifications(prev => [newNotif, ...prev]);
    };
    window.addEventListener('add-notification', handleAddNotif);
    return () => window.removeEventListener('add-notification', handleAddNotif);
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const handleAcknowledge = async (alertId) => {
    try {
      await client.post(`/alerts/${alertId}/acknowledge`);
      setNotifications(prev => prev.map(n => n.id === alertId ? { ...n, status: 'ACKNOWLEDGED' } : n));
      // Dispatch event to sync other views (e.g. Dashboard)
      window.dispatchEvent(new Event('alerts-updated'));
    } catch (err) {
      console.error("Failed to acknowledge alert from notification panel:", err);
    }
  };

  const handleNotificationClick = (notif) => {
    setIsOpen(false);
    if (notif.cveId) {
      // Redirect to playbooks page and pass cveId to highlight it
      navigate('/playbooks', { state: { selectedCveId: notif.cveId } });
    } else {
      // Redirect to home page
      navigate('/');
    }
  };

  const unreadCount = notifications.filter(n => n.type === 'custom' || n.status === 'UNRESOLVED').length;

  const NavItem = ({ to, icon: Icon, label }) => (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-4 px-5 py-4 rounded-xl transition-all duration-200 ${isCollapsed ? 'justify-center px-0 w-12 h-12 mx-auto' : ''
        } ${isActive
          ? 'bg-blue-500/25 text-blue-400 border border-blue-500/40 shadow-[0_0_20px_rgba(59,130,246,0.2)] font-semibold'
          : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
        }`
      }
    >
      <Icon size={22} className="shrink-0" />
      {!isCollapsed && (
        <span className="text-base tracking-wide font-medium">{label}</span>
      )}
    </NavLink>
  );

  return (
    <div className="flex h-screen w-full bg-[#0a0e1a] text-slate-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <div className={`flex flex-col border-r border-slate-800/60 bg-[#0d1222] shadow-2xl relative z-10 shrink-0 transition-all duration-300 ${isSidebarOpen ? (isCollapsed ? 'w-20' : 'w-60') : 'w-0 overflow-hidden border-r-0'
        }`}>
        <div className={`p-6 border-b border-slate-800/60 flex items-center gap-3 justify-center ${isCollapsed ? 'px-2' : ''}`}>
          <ShieldAlert size={32} className="text-blue-500 animate-pulse shrink-0" />
          {!isCollapsed && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <h1 className="text-xl font-black tracking-tight text-white leading-none">Cyberdefense</h1>
              <p className="text-xs text-blue-500 font-mono mt-1.5 uppercase font-bold tracking-widest">AI</p>
            </motion.div>
          )}
        </div>

        <nav className="flex-1 flex flex-col gap-2.5 p-4">
          <NavItem to="/" icon={Home} label="Home" />
          <NavItem to="/graph" icon={Network} label="Knowledge Graph" />
          <NavItem to="/playbooks" icon={BookOpen} label="Playbooks" />
          <NavItem to="/twin" icon={Cpu} label="Digital Twin" />

          {/* Collapse Toggle Button */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="mt-auto flex items-center justify-center w-12 h-12 mx-auto rounded-xl text-slate-500 hover:text-slate-200 hover:bg-slate-800/40 transition-all duration-200"
            title={isCollapsed ? "Expand Menu" : "Collapse Menu"}
          >
            {isCollapsed ? <ChevronRight size={22} className="shrink-0" /> : <ChevronLeft size={22} className="shrink-0" />}
          </button>
        </nav>

        <div className="p-4 border-t border-slate-800/60 flex justify-center">
          {isCollapsed ? (
            <div className="w-8 h-8 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center">
              <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse"></div>
            </div>
          ) : (
            <div className="flex items-center gap-3 px-3 py-2 rounded-md bg-green-500/10 border border-green-500/20 shadow-[0_0_10px_rgba(34,197,94,0.05)] w-full">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
              <span className="text-xs font-mono text-green-400">SYSTEM SECURE</span>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden relative">
        {/* Top Header Bar */}
        <div className="h-12 border-b border-slate-800/60 bg-[#0d1222]/90 backdrop-blur px-6 flex items-center justify-between z-30 shrink-0 relative">
          <div className="text-sm font-semibold text-slate-400 flex items-center gap-3">
            <button
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="p-1.5 hover:bg-slate-800 rounded text-slate-455 hover:text-white transition-all flex items-center justify-center shrink-0"
              title={isSidebarOpen ? "Hide Navigation Menu" : "Show Navigation Menu"}
            >
              <Menu size={18} />
            </button>
            <span className="text-slate-200 font-bold tracking-wide text-sm">
              {location.pathname === '/' ? 'Home' :
                location.pathname === '/graph' ? 'Knowledge Graph' :
                  location.pathname === '/playbooks' ? 'Playbooks' :
                      location.pathname === '/twin' ? 'Digital Twin' : 'SOC'}
            </span>
          </div>

          <div className="flex items-center gap-4 relative" ref={dropdownRef}>
            {/* Bell Button */}
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="p-2 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl text-slate-400 hover:text-white transition-all relative flex items-center justify-center hover:bg-slate-800/60"
            >
              <Bell size={18} className={unreadCount > 0 ? 'animate-pulse text-blue-400' : ''} />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-rose-500 text-white font-bold text-[9px] w-4 h-4 flex items-center justify-center rounded-full shadow-[0_0_8px_rgba(244,63,94,0.6)]">
                  {unreadCount}
                </span>
              )}
            </button>

            {/* Dropdown Panel */}
            <AnimatePresence>
              {isOpen && (
                <motion.div
                  initial={{ opacity: 0, y: 10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 10, scale: 0.95 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 top-12 w-96 bg-[#0f172a] border border-slate-800 rounded-2xl shadow-[0_10px_30px_rgba(0,0,0,0.5)] overflow-hidden z-50 flex flex-col max-h-[480px]"
                >
                  <div className="p-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Security Notifications</span>
                    <button
                      onClick={() => {
                        setNotifications([]);
                        setIsOpen(false);
                      }}
                      className="text-[10px] font-bold text-slate-500 hover:text-slate-300 uppercase tracking-wide transition-colors"
                    >
                      Clear All
                    </button>
                  </div>

                  <div className="flex-1 overflow-y-auto max-h-[400px] [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-slate-800">
                    {notifications.length === 0 ? (
                      <div className="p-10 text-center text-slate-500 text-xs flex flex-col gap-2 items-center justify-center">
                        <Bell size={24} className="opacity-30" />
                        <span>No active notifications.</span>
                      </div>
                    ) : (
                      notifications.map(n => {
                        const isAlert = n.type === 'alert';
                        const isUnresolved = !isAlert || n.status === 'UNRESOLVED';
                        return (
                          <div
                            key={n.id}
                            className={`p-4 border-b border-slate-800/40 hover:bg-slate-850/40 transition-colors cursor-pointer flex flex-col gap-1.5 relative ${isUnresolved ? 'bg-slate-900/10' : 'opacity-50'
                              }`}
                            onClick={() => handleNotificationClick(n)}
                          >
                            {/* Top Line: Message type & Time */}
                            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                              <span className="flex items-center gap-1.5 font-bold">
                                {isAlert ? (
                                  <>
                                    <span className={`w-1.5 h-1.5 rounded-full ${n.severity === 'CRITICAL' ? 'bg-red-500' :
                                        n.severity === 'HIGH' ? 'bg-amber-500' : 'bg-blue-500'
                                      }`} />
                                    {n.severity} ALERT
                                  </>
                                ) : (
                                  <>
                                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                                    SYSTEM
                                  </>
                                )}
                              </span>
                              <span>{n.timestamp ? n.timestamp.replace('T', ' ').substring(0, 16) : 'Just now'}</span>
                            </div>

                            {/* Message Text */}
                            <p className="text-xs text-slate-200 leading-relaxed font-semibold">
                              {n.message}
                            </p>

                            {/* Action buttons (Acknowledge) */}
                            {isAlert && n.cveId && n.status === 'UNRESOLVED' && (
                              <div className="flex justify-end pt-1">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation(); // Prevent navigation
                                    handleAcknowledge(n.id);
                                  }}
                                  className="px-2 py-0.5 bg-amber-500/10 hover:bg-amber-500/25 border border-amber-500/30 hover:border-amber-500/50 text-amber-400 rounded text-[9px] font-bold uppercase tracking-wider flex items-center gap-1 transition-all"
                                >
                                  Acknowledge
                                </button>
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Subtle grid background overlay */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTEgMWgyMHYyMEgxVjF6IiBmaWxsPSJub25lIiBzdHJva2U9InJnYmEoMjU1LDI1NSwyNTUsMC4wMykiIHN0cm9rZS13aWR0aD0iMScvPjwvc3ZnPg==')] opacity-50 pointer-events-none mt-12"></div>

        <div className={`flex-1 z-10 ${isTwin ? 'overflow-hidden' : 'overflow-auto p-6'}`}>
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<AnimatedPage><Dashboard /></AnimatedPage>} />
              <Route path="/graph" element={<AnimatedPage><KnowledgeGraph /></AnimatedPage>} />
              <Route path="/playbooks" element={<AnimatedPage><PlaybookViewer /></AnimatedPage>} />
              <Route path="/twin" element={<AnimatedPage><DigitalTwin /></AnimatedPage>} />
            </Routes>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

const AnimatedPage = ({ children }) => (
  <motion.div
    initial={{ opacity: 0, y: 15 }}
    animate={{ opacity: 1, y: 0 }}
    exit={{ opacity: 0, y: -15 }}
    transition={{ duration: 0.25, ease: 'easeInOut' }}
    className="h-full w-full"
  >
    {children}
  </motion.div>
);

export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
