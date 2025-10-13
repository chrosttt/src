let currentToken = null;
let currentRole = null;

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('signup-btn').onclick = signup;
  document.getElementById('login-btn').onclick = login;
  document.getElementById('profile-btn').onclick = getProfile;
});

async function signup() {
  const username = document.getElementById('signup-user').value;
  const password = document.getElementById('signup-pass').value;

  const res = await fetch('/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  alert(data.message);
}

async function login() {
  const username = document.getElementById('login-user').value;
  const password = document.getElementById('login-pass').value;

  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();

  if (data.token) {
    currentToken = data.token;
    currentRole = data.role;
    alert(data.message);

    if (currentRole === 'admin' && !document.getElementById('admin-btn')) {
      const btn = document.createElement('button');
      btn.id = 'admin-btn';
      btn.innerText = 'Admin Feature';
      btn.onclick = getAdmin;
      document.body.appendChild(btn);
    }
  } else {
    alert(data.message);
  }
}

async function getProfile() {
  if (!currentToken) return alert('Login first');

  const res = await fetch('/profile', {
    headers: { 'Authorization': 'Bearer ' + currentToken }
  });
  const data = await res.json();
  alert(`${data.message}\nRole: ${data.role}`);
}

async function getAdmin() {
  const res = await fetch('/admin', {
    headers: { 'Authorization': 'Bearer ' + currentToken }
  });
  const data = await res.json();
  alert(data.message);
}
// --------------------
// Dark/Light Mode Functions
// --------------------

// Set a cookie
function setCookie(name, value, days) {
  let expires = "";
  if (days) {
    let date = new Date();
    date.setTime(date.getTime() + (days*24*60*60*1000));
    expires = "; expires=" + date.toUTCString();
  }
  document.cookie = name + "=" + (value || "") + expires + "; path=/";
}

// Get a cookie
function getCookie(name) {
  const nameEQ = name + "=";
  const ca = document.cookie.split(';');
  for(let i = 0; i < ca.length; i++) {
    let c = ca[i].trim();
    if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
  }
  return null;
}

// Apply saved theme on page load
function applySavedTheme() {
  const savedTheme = getCookie("theme") || localStorage.getItem("theme");
  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
  } else {
    document.body.classList.remove("dark-mode");
  }
}

// Toggle dark/light mode
// Fonction pour changer le thème avec le bouton
function toggleTheme() {
  var element = document.body;
  element.classList.toggle("dark-mode");

  // Déterminer le thème actuel
  let currentTheme = element.classList.contains("dark-mode") ? "dark" : "light";

  // Sauvegarder dans localStorage
  localStorage.setItem("theme", currentTheme);

  // Sauvegarder aussi dans un cookie valable 7 jours
  setCookie("theme", currentTheme, 7);
}

// Appliquer le thème dès le chargement de la page
window.onload = applySavedTheme;
