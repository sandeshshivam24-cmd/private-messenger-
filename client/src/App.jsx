import { useEffect, useState } from 'react';
import LoginScreen from './components/LoginScreen';
import AdminPanel from './components/AdminPanel';
import Messenger from './components/Messenger';
import { apiFetch } from './lib/api';
import { getOrCreateIdentity } from './lib/crypto';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('pm_token') || '');
  const [currentUser, setCurrentUser] = useState(null);
  const [contacts, setContacts] = useState([]);
  const [adminUsers, setAdminUsers] = useState([]);
  const [loading, setLoading] = useState(!!token);
  const [error, setError] = useState('');

  const clearAuth = () => {
    localStorage.removeItem('pm_token');
    setToken('');
    setCurrentUser(null);
    setContacts([]);
    setAdminUsers([]);
    setError('');
  };

  const publishPublicKey = async (tok, username) => {
    try {
      const { publicJwk } = await getOrCreateIdentity(username);
      await apiFetch('/keys', {
        token: tok,
        method: 'POST',
        body: { publicKey: publicJwk }
      });
    } catch (err) {
      // Non-fatal: chat will retry deriving keys per-message and surface an error there.
      console.error('Failed to publish public key', err);
    }
  };

  const loadSession = async (tok) => {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/me', { token: tok });
      setCurrentUser(data.user);
      setContacts(data.contacts || []);
      localStorage.setItem('pm_token', tok);
      setToken(tok);

      await publishPublicKey(tok, data.user.username);

      if (data.user.role === 'admin') {
        const usersData = await apiFetch('/admin/users', { token: tok });
        setAdminUsers(usersData.users || []);
      }
    } catch (err) {
      clearAuth();
      setError('');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) loadSession(token);
    else setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    function setAppHeight() {
      const vh = window.visualViewport ? window.visualViewport.height : window.innerHeight;
      document.documentElement.style.setProperty('--app-height', `${vh}px`);
    }

    window.addEventListener('resize', setAppHeight);
    window.visualViewport?.addEventListener('resize', setAppHeight);
    setAppHeight();

    return () => {
      window.removeEventListener('resize', setAppHeight);
      window.visualViewport?.removeEventListener('resize', setAppHeight);
    };
  }, []);

  const handleLogin = async (username, password) => {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/login', {
        method: 'POST',
        body: { username, password }
      });

      localStorage.setItem('pm_token', data.token);
      setToken(data.token);
      setCurrentUser(data.user);
      setContacts(data.contacts || []);

      await publishPublicKey(data.token, data.user.username);

      if (data.user.role === 'admin') {
        const usersData = await apiFetch('/admin/users', {
          token: data.token
        });
        setAdminUsers(usersData.users || []);
      } else {
        setAdminUsers([]);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const refreshAdminUsers = async () => {
    if (!token || currentUser?.role !== 'admin') return;
    const data = await apiFetch('/admin/users', { token });
    setAdminUsers(data.users || []);
  };

  if (loading && !currentUser) {
    return <div className="app-loading">Loading...</div>;
  }

  if (!currentUser) {
    return (
      <LoginScreen
        onLogin={handleLogin}
        loading={loading}
        error={error}
      />
    );
  }

  if (currentUser.role === 'admin') {
    return (
      <AdminPanel
        token={token}
        currentUser={currentUser}
        onLogout={clearAuth}
        users={adminUsers}
        onRefreshUsers={refreshAdminUsers}
      />
    );
  }

  return (
    <Messenger
      token={token}
      currentUser={currentUser}
      onLogout={clearAuth}
    />
  );
}
