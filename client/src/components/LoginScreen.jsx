import { useState } from 'react';

export default function LoginScreen({ onLogin, loading, error }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="brand-mark">PM</div>
        <h1>Private Messenger</h1>
        <p>Username aur password se login karein.</p>

        <form
          className="login-form"
          onSubmit={(e) => {
            e.preventDefault();
            onLogin(username, password);
          }}
        >
          <label>
            Username
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin / rahul01"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </label>
          {error ? <div className="error-box">{error}</div> : null}
          <button className="primary-btn" disabled={loading}>
            {loading ? 'Signing in...' : 'Login'}
          </button>
        </form>

        <div className="hint-card">
          Demo accounts:
          <div>admin / admin123</div>
          <div>rahul01 / pass123!</div>
        </div>
      </div>
    </div>
  );
}
