import { createContext, useContext, useState, useEffect } from 'react';


const DEFAULT_NAME = 'Qumulo Replication Monitor';

const AppSettingsContext = createContext({
  appName: DEFAULT_NAME,
  setAppName: () => {},
});

export function AppSettingsProvider({ children }) {
  const [appName, setAppNameState] = useState(
    () => localStorage.getItem('qm_app_name') || DEFAULT_NAME
  );

  const setAppName = (name) => {
    const n = name || DEFAULT_NAME;
    setAppNameState(n);
    document.title = n;
    localStorage.setItem('qm_app_name', n);
  };

  // Fetch once on mount using public endpoint (no auth required)
  useEffect(() => {
    document.title = localStorage.getItem('qm_app_name') || DEFAULT_NAME;
    fetch('/api/settings/public')
      .then(r => r.ok ? r.json() : null)
      .then(s => { if (s?.app_name) setAppName(s.app_name); })
      .catch(() => {});
  }, []);

  return (
    <AppSettingsContext.Provider value={{ appName, setAppName }}>
      {children}
    </AppSettingsContext.Provider>
  );
}

export const useAppSettings = () => useContext(AppSettingsContext);
