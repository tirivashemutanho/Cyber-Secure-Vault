// Hacker Web App Logic
const API = '';

function setToken(token) {
  localStorage.setItem('jwt_token', token);
}
function getToken() {
  return localStorage.getItem('jwt_token');
}
function clearToken() {
  localStorage.removeItem('jwt_token');
}

// Navigation guard
const page = window.location.pathname.split('/').pop();
if (page === 'upload.html' && !getToken()) {
  window.location = 'login.html';
}
if ((page === 'login.html' || page === 'register.html') && getToken()) {
  window.location = 'upload.html';
}

// Register
if (document.getElementById('registerBtn')) {
  document.getElementById('registerBtn').onclick = function() {
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    fetch(API + '/register', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username, password})
    }).then(res => res.json())
    .then(data => {
      if(data.msg === 'User created'){
        document.getElementById('registerMsg').innerText = 'Registration successful! Redirecting to login...';
        setTimeout(() => window.location = 'login.html', 1200);
      } else {
        document.getElementById('registerMsg').innerText = data.msg || 'Registration failed';
      }
    });
  }
}

// Login
if (document.getElementById('loginBtn')) {
  document.getElementById('loginBtn').onclick = function() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    fetch(API + '/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username, password})
    }).then(res => res.json())
    .then(data => {
      if(data.access_token){
        setToken(data.access_token);
        document.getElementById('loginMsg').innerText = 'Login successful! Redirecting...';
        setTimeout(() => window.location = 'upload.html', 1000);
      } else {
        document.getElementById('loginMsg').innerText = data.msg || 'Login failed';
      }
    });
  }
}

// Upload & File List
if (document.getElementById('uploadBtn')) {
  // Check auth
  if (!getToken()) {
    window.location = 'login.html';
  }
  // Logout
  document.getElementById('logoutBtn').onclick = function() {
    clearToken();
    window.location = 'login.html';
  }
  // Upload
  document.getElementById('uploadBtn').onclick = function() {
    const fileInput = document.getElementById('fileInput');
    if(fileInput.files.length === 0){
      alert('Select a file first!');
      return;
    }
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    fetch(API + '/upload', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + getToken() },
      body: formData
    })
    .then(async res => {
      let data;
      try {
        data = await res.json();
      } catch (e) {
        document.getElementById('uploadMsg').innerText = 'Upload failed: Invalid server response.';
        return;
      }
      if (data.trace) {
        document.getElementById('uploadMsg').innerText = (data.msg || 'Upload failed') + '\n' + data.error + '\n' + data.trace;
      } else {
        document.getElementById('uploadMsg').innerText = data.msg || 'Upload failed';
      }
      loadFiles();
    });
  }
  // Load files
  function loadFiles() {
    fetch(API + '/files', {
      headers: { 'Authorization': 'Bearer ' + getToken() }
    }).then(res => res.json())
    .then(files => {
      const list = document.getElementById('files');
      list.innerHTML = '';
      files.forEach(f => {
        const li = document.createElement('li');
        const link = document.createElement('a');
        link.href = '#';
        link.innerText = f;
        link.onclick = function(e) {
          e.preventDefault();
          downloadFile(f);
        };
        li.appendChild(link);
        list.appendChild(li);
      });
    });
  }
  function downloadFile(filename) {
    fetch(API + '/download/' + encodeURIComponent(filename), {
      headers: { 'Authorization': 'Bearer ' + getToken() }
    })
    .then(res => {
      if (!res.ok) throw new Error('Download failed');
      return res.blob();
    })
    .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    })
    .catch(err => {
      alert('Download failed: ' + err.message);
    });
  }
  // Initial load
  loadFiles();
} 