import { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

const AppSettingsContext = createContext({
  appName: 'Qumulo Replication Monitor',
  setAppName: () => {},
});

export function AppSettingsProvider({ children }) {
  const [appName, setAppNameState] = useState(() => {
    return localStorage.getItem('qm_app_name') || 'Qumulo Replication Monitor';
  });

  const setAppName = (name) => {
    setAppNameState(name);
    document.title = name;
    localStorage.setItem('qm_app_name', name);
  };

  useEffect(() => {
    api.settings().then(s => {
      if (s.app_name) setAppName(s.app_name);
      else document.title = appName;
    }).catch(() => {
      document.title = appName;
    });
  }, []);

  return (
    <AppSettingsContext.Provider value={{ appName, setAppName }}>
      {children}
    </AppSettingsContext.Provider>
  );
}

export const useAppSettings = () => useContext(AppSettingsContext);
