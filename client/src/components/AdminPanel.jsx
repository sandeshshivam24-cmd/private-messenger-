import { useMemo, useState } from 'react';
import { apiFetch } from '../lib/api';

export default function AdminPanel({ token, currentUser, onLogout, users, onRefreshUsers }) {
  const [form, setForm] = useState({ username: '', displayName: '', password: '' });
  const [selected, setSelected] = useState(null);
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const sortedUsers = useMemo(() => users.filter((u) => u.id !== currentUser.id), [users, currentUser.id]);

  const resetForm = () => setForm({ username: '', displayName: '', password: '' });

  const refresh = async () => {
    await onRefreshUsers();
  };

  const createUser = async (e) => {
    e.preventDefault();
    setBusy(true);
    setStatus('');
    try {
      await apiFetch('/api/admin/users', {
        token,
        method: 'POST',
        body: {
          username: form.username,
          displayName: form.displayName,
          password: form.password,
          showLastSeen: true
        }
      });
      resetForm();
      setStatus('User created.');
      await refresh();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setBusy(false);
    }
  };

  const updateUser = async (id, patch) => {
    setBusy(true);
    setStatus('');
    try {
      await apiFetch(`/api/admin/users/${id}`, {
        token,
        method: 'PATCH',
        body: patch
      });
      setStatus('Updated.');
      await refresh();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setBusy(false);
    }
  };

  const removeUser = async (id) => {
    if (!confirm('Delete user permanently?')) return;
    setBusy(true);
    setStatus('');
    try {
      await apiFetch(`/api/admin/users/${id}`, { token, method: 'DELETE' });
      setStatus('User deleted.');
      await refresh();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleUser = async (u) => {
    setBusy(true);
    setStatus('');
    try {
      await apiFetch(`/api/admin/users/${u.id}/${u.enabled ? 'disable' : 'enable'}`, {
        token,
        method: 'POST'
      });
      setStatus(u.enabled ? 'User disabled.' : 'User enabled.');
      await refresh();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setBusy(false);
    }
  };

  const resetPassword = async (id) => {
    const password = prompt('New password');
    if (!password) return;
    await updateUser(id, { password });
  };

  return (
    <div className="panel-shell">
      <aside className="sidebar">
        <div className="sidebar-top">
          <div>
            <div className="small-label">Admin</div>
            <div className="title-strong">{currentUser.displayName}</div>
          </div>
          <button className="ghost-btn" onClick={onLogout}>Logout</button>
        </div>

        <form className="admin-form card" onSubmit={createUser}>
          <h3>Create User</h3>
          <input
            placeholder="Username"
            value={form.username}
            onChange={(e) => setForm((s) => ({ ...s, username: e.target.value }))}
          />
          <input
            placeholder="Display Name"
            value={form.displayName}
            onChange={(e) => setForm((s) => ({ ...s, displayName: e.target.value }))}
          />
          <input
            placeholder="Password"
            type="password"
            value={form.password}
            onChange={(e) => setForm((s) => ({ ...s, password: e.target.value }))}
          />
          <button className="primary-btn" disabled={busy}>Create</button>
        </form>

        <div className="status-note">{status || 'Manage users from here.'}</div>
      </aside>

      <main className="content">
        <div className="content-head">
          <h2>User Management</h2>
          <span className="muted">{sortedUsers.length} users</span>
        </div>

        <div className="admin-list">
          {sortedUsers.map((u) => (
            <div key={u.id} className="admin-row card">
              <div className="avatar initials">{u.initials}</div>
              <div className="row-main">
                <div className="row-title">
                  <strong>{u.displayName}</strong>
                  <span>@{u.username}</span>
                </div>
                <div className="row-sub">
                  <span className={u.online ? 'online-pill' : 'offline-pill'}>
                    {u.online ? 'Online' : 'Offline'}
                  </span>
                  <span className="muted">{u.enabled ? 'Enabled' : 'Disabled'}</span>
                  <span className="muted">Last seen: {u.lastSeen ? new Date(u.lastSeen).toLocaleString() : 'Never'}</span>
                </div>
              </div>
              <div className="row-actions">
                <button className="ghost-btn" onClick={() => setSelected(u.id)} disabled={busy}>Edit</button>
                <button className="ghost-btn" onClick={() => resetPassword(u.id)} disabled={busy}>Reset</button>
                <button className="ghost-btn" onClick={() => toggleUser(u)} disabled={busy}>
                  {u.enabled ? 'Disable' : 'Enable'}
                </button>
                <button className="danger-btn" onClick={() => removeUser(u.id)} disabled={busy}>Delete</button>
              </div>

              {selected === u.id ? (
                <div className="inline-editor">
                  <input
                    defaultValue={u.displayName}
                    id={`dn-${u.id}`}
                    placeholder="Display Name"
                  />
                  <label className="checkline">
                    <input
                      type="checkbox"
                      defaultChecked={u.showLastSeen}
                      id={`ls-${u.id}`}
                    />
                    Show last seen
                  </label>
                  <div className="inline-actions">
                    <button
                      className="primary-btn"
                      onClick={() => {
                        const displayName = document.getElementById(`dn-${u.id}`).value;
                        const showLastSeen = document.getElementById(`ls-${u.id}`).checked;
                        updateUser(u.id, { displayName, showLastSeen });
                        setSelected(null);
                      }}
                      disabled={busy}
                    >
                      Save
                    </button>
                    <button className="ghost-btn" onClick={() => setSelected(null)} disabled={busy}>Cancel</button>
                  </div>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
