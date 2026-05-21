import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { LayoutDashboard, Network, Bell, BookOpen, ShieldAlert, Cpu } from 'lucide-react';
import Dashboard from './components/Dashboard';
import KnowledgeGraph from './components/KnowledgeGraph';
import AlertPanel from './components/AlertPanel';
import PlaybookViewer from './components/PlaybookViewer';
import RedTeamSim from './components/RedTeamSim';
import DigitalTwin from './components/DigitalTwin';

function AppContent() {
  const location = useLocation();
  const isTwin = location.pathname === '/twin';

  const NavItem = ({ to, icon: Icon, label }) => (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-4 px-5 py-4 rounded-xl transition-all duration-200 ${
          isActive 
            ? 'bg-blue-500/25 text-blue-400 border border-blue-500/40 shadow-[0_0_20px_rgba(59,130,246,0.2)] font-semibold' 
            : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
        }`
      }
    >
      <Icon size={22} className="shrink-0" />
      <span className="text-base tracking-wide font-medium">{label}</span>
    </NavLink>
  );

  return (
    <div className="flex h-screen w-full bg-[#0a0e1a] text-slate-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <div className="w-60 flex flex-col border-r border-slate-800/60 bg-[#0d1222] shadow-2xl relative z-10 shrink-0">
        <div className="p-6 border-b border-slate-800/60 flex items-center gap-3">
           <ShieldAlert size={32} className="text-blue-500 animate-pulse" />
           <div>
              <h1 className="text-xl font-black tracking-tight text-white leading-none">Cyberdefense</h1>
              <p className="text-xs text-blue-500 font-mono mt-1.5 uppercase font-bold tracking-widest">AI</p>
           </div>
        </div>
        
        <nav className="flex-1 flex flex-col gap-2.5 p-4">
          <NavItem to="/" icon={LayoutDashboard} label="Dashboard" />
          <NavItem to="/graph" icon={Network} label="Knowledge Graph" />
          <NavItem to="/alerts" icon={Bell} label="Alerts" />
          <NavItem to="/playbooks" icon={BookOpen} label="Playbooks" />
          <NavItem to="/redteam" icon={ShieldAlert} label="Red Team" />
          <NavItem to="/twin" icon={Cpu} label="Digital Twin" />
        </nav>
        
        <div className="p-4 border-t border-slate-800/60">
           <div className="flex items-center gap-3 px-3 py-2 rounded-md bg-green-500/10 border border-green-500/20 shadow-[0_0_10px_rgba(34,197,94,0.05)]">
             <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
             <span className="text-xs font-mono text-green-400">SYSTEM SECURE</span>
           </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden relative">
        {/* Subtle grid background overlay */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTEgMWgyMHYyMEgxVjF6IiBmaWxsPSJub25lIiBzdHJva2U9InJnYmEoMjU1LDI1NSwyNTUsMC4wMykiIHN0cm9rZS13aWR0aD0iMScvPjwvc3ZnPg==')] opacity-50 pointer-events-none"></div>
        
        <div className={`flex-1 z-10 ${isTwin ? 'overflow-hidden' : 'overflow-auto p-6'}`}>
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<AnimatedPage><Dashboard /></AnimatedPage>} />
              <Route path="/graph" element={<AnimatedPage><KnowledgeGraph /></AnimatedPage>} />
              <Route path="/alerts" element={<AnimatedPage><AlertPanel /></AnimatedPage>} />
              <Route path="/playbooks" element={<AnimatedPage><PlaybookViewer /></AnimatedPage>} />
              <Route path="/redteam" element={<AnimatedPage><RedTeamSim /></AnimatedPage>} />
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
