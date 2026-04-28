import { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

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

  // Fetch once on mount — no dependencies so it never re-runs
  useEffect(() => {
    api.settings()
      .then(s => { if (s?.app_name) setAppName(s.app_name); })
      .catch(() => {});
    // Set title from cached value immediately while fetch is in flight
    document.title = localStorage.getItem('qm_app_name') || DEFAULT_NAME;
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <AppSettingsContext.Provider value={{ appName, setAppName }}>
      {children}
    </AppSettingsContext.Provider>
  );
}

export const useAppSettings = () => useContext(AppSettingsContext);
