

(function () {
    // --- utils ---
    const USERS_KEY = 'lms_users_v1';
    const SESSION_KEY = 'lms_session_v1';
  
    // convert ArrayBuffer to hex
    function toHex(buffer) {
      const bytes = new Uint8Array(buffer);
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  
    // hash text using SHA-256 -> hex
    async function hashText(text) {
      const enc = new TextEncoder();
      const data = enc.encode(text);
      const digest = await crypto.subtle.digest('SHA-256', data);
      return toHex(digest);
    }
  
    function readUsers() {
      try {
        return JSON.parse(localStorage.getItem(USERS_KEY) || '[]');
      } catch {
        return [];
      }
    }
    function writeUsers(users) {
      localStorage.setItem(USERS_KEY, JSON.stringify(users));
    }
  
    // session: object { email, name, createdAt }
    const auth = {
      async register(profile, password) {
        if (!profile || !profile.email || !password) throw new Error('Invalid input');
        const users = readUsers();
        const existing = users.find(u => u.email.toLowerCase() === profile.email.toLowerCase());
        if (existing) throw new Error('Email already registered');
        const pwHash = await hashText(password);
        const newUser = { email: profile.email.toLowerCase(), name: profile.name || profile.email, pwHash };
        users.push(newUser);
        writeUsers(users);
        return newUser;
      },
  
      async login(email, password, remember = false) {
        if (!email || !password) throw new Error('Provide email & password');
        const users = readUsers();
        const user = users.find(u => u.email === email.toLowerCase());
        if (!user) throw new Error('Account not found');
        const h = await hashText(password);
        if (h !== user.pwHash) throw new Error('Incorrect password');
        const session = { email: user.email, name: user.name, createdAt: new Date().toISOString() };
        const sStr = JSON.stringify(session);
        if (remember) localStorage.setItem(SESSION_KEY, sStr);
        else sessionStorage.setItem(SESSION_KEY, sStr);
        return session;
      },
  
      logout(redirect = 'index.html') {
        localStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_KEY);
        if (redirect) window.location.href =redirect;
      },
  
      currentUser() {
        const s = sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY);
        return s ? JSON.parse(s) : null;
      },
  
      requireAuth(redirectTo = 'index.html') {
        const u = auth.currentUser();
        if (!u) {
          // preserve intended url so we can redirect after login
          const intended = window.location.pathname + window.location.search;
          localStorage.setItem('lms_intended', intended);
          window.location.href = redirectTo;
          return false;
        }
        return true;
      },
  
      // simple forgot password simulation: creates a one-time code and stores it in localStorage
      sendResetCode(email) {
        const users = readUsers();
        const user = users.find(u => u.email === (email || '').toLowerCase());
        if (!user) throw new Error('Account not found');
        // create 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // store {code, email, expires}
        const payload = { code, email: user.email, expires: Date.now() + 15 * 60 * 1000 }; // 15 minutes
        localStorage.setItem('lms_reset_' + user.email, JSON.stringify(payload));
        return code; // in production you would email this
      },
  
      async verifyAndReset(email, code, newPassword) {
        const key = 'lms_reset_' + (email || '').toLowerCase();
        const raw = localStorage.getItem(key);
        if (!raw) throw new Error('No reset requested for this email');
        const payload = JSON.parse(raw);
        if (payload.expires < Date.now()) {
          localStorage.removeItem(key);
          throw new Error('Reset code expired');
        }
        if (payload.code !== String(code).trim()) throw new Error('Invalid code');
        // update the user's password
        const users = readUsers();
        const user = users.find(u => u.email === payload.email);
        if (!user) throw new Error('Account not found');
        user.pwHash = await hashText(newPassword);
        writeUsers(users);
        localStorage.removeItem(key);
        return true;
      }
    };
  
    // expose to window
    window.auth = auth;
  
    // -------------------------
    // UI logic for login.html
    // -------------------------
    function $(sel, root=document) { return root.querySelector(sel); }
    function $all(sel, root=document) { return Array.from(root.querySelectorAll(sel)); }
  
    document.addEventListener('DOMContentLoaded', () => {
      // If already logged in, redirect to index
      const current = auth.currentUser();
      if (current && window.location.pathname.endsWith('login.html')) {
        // If there was an intended page saved earlier, redirect there once
        const intended = localStorage.getItem('lms_intended');
        if (intended) { localStorage.removeItem('lms_intended'); window.location.href = intended; return; }
        window.location.href = 'index.html';
        return;
      }
  
      // tabs
      const tabs = $all('.tab');
      tabs.forEach(t => t.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        const tab = t.dataset.tab;
        $all('form').forEach(f => f.style.display = (f.id === 'form-' + tab) ? 'block' : 'none');
        $('#message').innerHTML = '';
      }));
  
      // simple message helper
      const showMsg = (text, ok = true) => {
        $('#message').innerHTML = `<div class="msg ${ok ? 'ok' : 'error'}">${text}</div>`;
      };
  
      // toggle pw show for login and register
      $('#toggle-login-pw').addEventListener('click', () => {
        const el = $('#login-password');
        el.type = el.type === 'password' ? 'text' : 'password';
      });
      $('#toggle-reg-pw').addEventListener('click', () => {
        const el = $('#reg-password');
        el.type = el.type === 'password' ? 'text' : 'password';
      });
  
      // password strength
      $('#reg-password').addEventListener('input', (e) => {
        const v = e.target.value;
        let score = 0;
        if (v.length >= 8) score++;
        if (/[A-Z]/.test(v)) score++;
        if (/[0-9]/.test(v)) score++;
        if (/[^A-Za-z0-9]/.test(v)) score++;
        const labels = ['Very weak','Weak','Okay','Strong','Very strong'];
        $('#pw-strength').textContent = `Password strength: ${labels[score]}`;
      });
  
      // REGISTER submit
      $('#form-register').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const name = $('#reg-name').value.trim();
        const email = $('#reg-email').value.trim();
        const pw = $('#reg-password').value;
        if (!name || !email || !pw) { showMsg('Fill all fields', false); return; }
        if (pw.length < 8) { showMsg('Password must be at least 8 characters', false); return; }
        try {
          await auth.register({ name, email }, pw);
          showMsg('Account created — you may now login.', true);
          // auto-switch to login
          const loginTab = tabs.find(t => t.dataset.tab === 'login');
          loginTab.click();
          $('#login-email').value = email;
        } catch (err) {
          showMsg(err.message || 'Registration failed', false);
        }
      });
  
      // LOGIN submit
      $('#form-login').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const email = $('#login-email').value.trim();
        const pw = $('#login-password').value;
        const remember = $('#remember').checked;
        try {
          await auth.login(email, pw, remember);
          showMsg('Login successful — redirecting...', true);
          // redirect to intended page if present
          const intended = localStorage.getItem('lms_intended');
          if (intended) { localStorage.removeItem('lms_intended'); window.location.href = intended; return; }
          setTimeout(() => window.location.href = 'Dashboard.html', 300);
        } catch (err) {
          showMsg(err.message || 'Login failed', false);
        }
      });
  
      // FORGOT: send code
      $('#btnSendCode').addEventListener('click', () => {
        const email = $('#forgot-email').value.trim();
        if (!email) { showMsg('Enter your email first', false); return; }
        try {
          const code = auth.sendResetCode(email);
          // For demo, show the code to the user as if emailed.
          showMsg(`Reset code (demo): ${code}. Use it below to reset your password.`, true);
        } catch (err) {
          showMsg(err.message || 'Could not send code', false);
        }
      });
  
      // FORGOT: perform reset
      $('#btnReset').addEventListener('click', async () => {
        const email = $('#forgot-email').value.trim();
        const code = $('#reset-code').value.trim();
        const npw = $('#reset-password').value;
        if (!email || !code || !npw) { showMsg('Fill email, code and new password', false); return; }
        if (npw.length < 8) { showMsg('Password must be at least 8 characters', false); return; }
        try {
          await auth.verifyAndReset(email, code, npw);
          showMsg('Password reset — you can now login.', true);
          // switch to login tab
          tabs.find(t => t.dataset.tab === 'login').click();
        } catch (err) {
          showMsg(err.message || 'Reset failed', false);
        }
      });
      let mng = document.querySelector(".nav-item[href='manage.html']");
      mng.addEventListener("click",()=>{
        window.location.href = "manage.html";
      });
     
  
      // helper nav links inside form (goto)
      $all('[data-goto]').forEach(el => el.addEventListener('click', (e) => {
        const t = el.dataset.goto;
        tabs.find(tab => tab.dataset.tab === t).click();
      }));
    });
  })();

 

  
