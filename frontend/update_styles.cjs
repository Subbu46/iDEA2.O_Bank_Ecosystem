const fs = require('fs');
const path = require('path');

const srcDir = 'd:/sarathi-cyberdefense/frontend/src/components';
const filesToUpdate = [
  'Dashboard.jsx',
  'KnowledgeGraph.jsx',
  'PlaybookViewer.jsx',
  'RedTeamSim.jsx',
  'AlertPanel.jsx',
  'PlaybookModal.jsx',
  'AttackReplayTimeline.jsx'
];

const classMap = {
  'bg-\\[#0f172a\\]': 'bg-white dark:bg-[#0f172a]',
  'bg-\\[#0f172a\\]\\/95': 'bg-white/95 dark:bg-[#0f172a]/95',
  'border-slate-800': 'border-slate-200 dark:border-slate-800',
  'text-slate-400': 'text-slate-600 dark:text-slate-400',
  'text-slate-100': 'text-slate-900 dark:text-slate-100',
  'text-slate-200': 'text-slate-800 dark:text-slate-200',
  'text-slate-300': 'text-slate-700 dark:text-slate-300',
  'text-slate-500': 'text-slate-500 dark:text-slate-500',
  'text-slate-600': 'text-slate-500 dark:text-slate-600',
  'bg-slate-900\\/60': 'bg-slate-50 dark:bg-slate-900/60',
  'bg-slate-950\\/70': 'bg-white dark:bg-slate-950/70',
  'bg-slate-950\\/20': 'bg-slate-50 dark:bg-slate-950/20',
  'bg-slate-900': 'bg-slate-50 dark:bg-slate-900',
  'bg-slate-800': 'bg-slate-100 dark:bg-slate-800',
  'hover:border-slate-700': 'hover:border-slate-300 dark:hover:border-slate-700',
  'hover:bg-slate-800\\/80': 'hover:bg-slate-100 dark:hover:bg-slate-800/80',
  'hover:bg-slate-900\\/60': 'hover:bg-slate-50 dark:hover:bg-slate-900/60',
  'hover:bg-slate-800': 'hover:bg-slate-100 dark:hover:bg-slate-800',
  'text-cyan-400': 'text-cyan-600 dark:text-cyan-400',
  'text-cyan-300': 'text-cyan-700 dark:text-cyan-300',
  'bg-cyan-950\\/20': 'bg-cyan-50 dark:bg-cyan-950/20',
  'bg-cyan-950\\/60': 'bg-cyan-100 dark:bg-cyan-950/60',
  'bg-cyan-955\\/40': 'bg-cyan-100 dark:bg-cyan-955/40',
  'border-cyan-500\\/40': 'border-cyan-300 dark:border-cyan-500/40',
  'border-cyan-500\\/20': 'border-cyan-200 dark:border-cyan-500/20',
  'bg-cyan-500\\/8': 'bg-cyan-50 dark:bg-cyan-500/8',
  'bg-cyan-500\\/10': 'bg-cyan-100 dark:bg-cyan-500/10',
  'hover:bg-cyan-500\\/20': 'hover:bg-cyan-200 dark:hover:bg-cyan-500/20',
  'border-cyan-500\\/35': 'border-cyan-300 dark:border-cyan-500/35',
  'hover:border-cyan-500\\/50': 'hover:border-cyan-400 dark:hover:border-cyan-500/50',
  'bg-red-500\\/15': 'bg-red-50 dark:bg-red-500/15',
  'border-red-500\\/60': 'border-red-300 dark:border-red-500/60',
  'text-red-400': 'text-red-600 dark:text-red-400',
  'bg-amber-500\\/10': 'bg-amber-50 dark:bg-amber-500/10',
  'border-amber-500\\/40': 'border-amber-300 dark:border-amber-500/40',
  'text-amber-400': 'text-amber-600 dark:text-amber-400',
  'bg-blue-500\\/10': 'bg-blue-50 dark:bg-blue-500/10',
  'border-blue-500\\/30': 'border-blue-300 dark:border-blue-500/30',
  'text-blue-400': 'text-blue-600 dark:text-blue-400',
  'bg-slate-500\\/10': 'bg-slate-50 dark:bg-slate-500/10',
  'border-slate-600\\/30': 'border-slate-300 dark:border-slate-600/30',
  'bg-slate-600\\/20': 'bg-slate-100 dark:bg-slate-600/20',
  'bg-red-500\\/20': 'bg-red-100 dark:bg-red-500/20',
  'bg-amber-500\\/20': 'bg-amber-100 dark:bg-amber-500/20',
  'bg-blue-500\\/20': 'bg-blue-100 dark:bg-blue-500/20',
  'bg-\\[#0d1222\\]': 'bg-white dark:bg-[#0d1222]',
  'bg-\\[#0a0e1a\\]': 'bg-slate-50 dark:bg-[#0a0e1a]',
  'border-slate-800\\/50': 'border-slate-200 dark:border-slate-800/50',
  'border-slate-800\\/60': 'border-slate-200 dark:border-slate-800/60',
  'border-slate-800\\/70': 'border-slate-200 dark:border-slate-800/70',
  'border-slate-700\\/50': 'border-slate-300 dark:border-slate-700/50',
  'border-slate-700\\/30': 'border-slate-300 dark:border-slate-700/30'
};

filesToUpdate.forEach(file => {
  const filePath = path.join(srcDir, file);
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Sort keys by length descending to prevent partial replacements (e.g. replacing 'bg-slate-900' inside 'bg-slate-900/60')
    const keys = Object.keys(classMap).sort((a, b) => b.length - a.length);
    
    keys.forEach(key => {
      // Regex to match the exact class bounded by quotes, spaces, or backticks
      // We use a lookaround to ensure we aren't replacing inside another class
      const regex = new RegExp("(?<=['\"`\\s])" + key + "(?=['\"`\\s])", 'g');
      content = content.replace(regex, classMap[key]);
    });

    fs.writeFileSync(filePath, content);
    console.log(`Updated ${file}`);
  }
});
