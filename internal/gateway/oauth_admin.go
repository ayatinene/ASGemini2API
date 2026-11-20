package gateway

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/auth"
)

const (
	oauthPagePath    = "/admin/oauth"
	oauthAttemptTTL  = 15 * time.Minute
	maxCallbackBytes = 8 << 10
)

// oauthPage renders a small self-contained login console. It is intentionally
// unauthenticated HTML: the page holds no secret, and every API call below
// still requires the admin Bearer key.
var oauthPage = template.Must(template.New("oauth").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASGemini2API · 授权</title>
<style>
:root{color-scheme:light dark;--bg:#0f1115;--panel:#171a21;--line:#2a2f3a;--text:#e6e8ee;--muted:#9aa3b2;--accent:#6ea8fe;--ok:#3fb950;--err:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans SC",sans-serif}
main{max-width:760px;margin:40px auto;padding:0 20px}
h1{font-size:20px;margin:0 0 4px}
p.sub{color:var(--muted);margin:0 0 24px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
label{display:block;font-weight:600;margin-bottom:6px}
input,textarea,button{font:inherit}
input,textarea{width:100%;background:#0d0f14;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px}
textarea{min-height:92px;resize:vertical}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
button{background:var(--accent);color:#08111f;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}
button.secondary{background:transparent;color:var(--text);border:1px solid var(--line)}
button:disabled{opacity:.55;cursor:not-allowed}
code,a.url{word-break:break-all;color:var(--accent)}
pre{white-space:pre-wrap;word-break:break-all;background:#0d0f14;border:1px solid var(--line);border-radius:8px;padding:10px;margin:10px 0 0}
#status{margin-top:6px;color:var(--muted)}
#status.ok{color:var(--ok)} #status.err{color:var(--err)}
small{color:var(--muted)}
</style></head>
<body><main>
<h1>Google 授权</h1>
<p class="sub">在管理端完成 Android Studio Gemini 的账号授权。密钥只保存在本页内存中，不会出现在 URL 里。</p>

<section>
  <label for="key">Admin Key</label>
  <input id="key" type="password" autocomplete="off" placeholder="ASGEMINI_ADMIN_KEY">
  <div class="row"><button id="start">生成授权链接</button><small>已存在未过期链接时会复用同一条</small></div>
</section>

<section>
  <label>1. 在浏览器打开授权链接</label>
  <div id="linkBox"><small>尚未生成</small></div>
  <div class="row"><button class="secondary" id="copy" disabled>复制链接</button></div>
  <p><small>授权后浏览器会停在无法连接的 <code>http://127.0.0.1:&lt;port&gt;/CALLBACK_AUTH?code=…&amp;state=…</code>，这是正常的。</small></p>
</section>

<section>
  <label for="callback">2. 粘贴浏览器地址栏里的完整回调 URL</label>
  <textarea id="callback" placeholder="http://127.0.0.1:14535/CALLBACK_AUTH?state=…&amp;code=…"></textarea>
  <div class="row"><button id="complete">完成授权</button><button class="secondary" id="statusBtn">查看账号状态</button></div>
</section>

<section><label>结果</label><div id="status">未开始</div></section>

<script>
(function(){
  var keyEl=document.getElementById('key'),statusEl=document.getElementById('status');
  var linkBox=document.getElementById('linkBox'),copyBtn=document.getElementById('copy');
  var authUrl='';
  function setStatus(text,cls){statusEl.textContent=text;statusEl.className=cls||'';}
  function headers(){return {'Content-Type':'application/json','Authorization':'Bearer '+keyEl.value.trim()};}
  function show(obj){setStatus(typeof obj==='string'?obj:JSON.stringify(obj,null,2), 'ok');}
  function showError(err){
    var msg=(err&&err.message)||'请求失败';
    var code=(err&&err.code)?(' ['+err.code+']'):'';
    setStatus(msg+code,'err');
  }
  function call(path,body){
    if(!keyEl.value.trim()){showError({message:'请先填写 Admin Key'});return Promise.reject();}
    return fetch(path,{method:'POST',headers:headers(),body:JSON.stringify(body||{})}).then(function(r){
      return r.json().then(function(j){ if(!r.ok){throw (j&&j.error)||{message:'HTTP '+r.status};} return j;});
    });
  }
  document.getElementById('start').onclick=function(){
    setStatus('正在生成…');
    call('/admin/oauth/start',{}).then(function(j){
      authUrl=j.auth_url||'';
      linkBox.innerHTML='';
      var a=document.createElement('a');a.href=authUrl;a.target='_blank';a.rel='noreferrer noopener';a.className='url';a.textContent=authUrl;
      linkBox.appendChild(a);
      if(j.reused){var s=document.createElement('small');s.textContent='（复用未过期链接）';linkBox.appendChild(document.createElement('br'));linkBox.appendChild(s);}
      copyBtn.disabled=!authUrl;
      setStatus('链接已生成，请在浏览器打开并完成授权。','ok');
    }).catch(showError);
  };
  copyBtn.onclick=function(){
    if(!authUrl)return;
    navigator.clipboard.writeText(authUrl).then(function(){setStatus('链接已复制。','ok');},function(){setStatus('复制失败，请手动选择链接。','err');});
  };
  document.getElementById('complete').onclick=function(){
    var cb=document.getElementById('callback').value.trim();
    if(!cb){showError({message:'请粘贴回调 URL'});return;}
    setStatus('正在交换授权码…');
    call('/admin/oauth/complete',{callback_url:cb}).then(function(j){show(j);}).catch(showError);
  };
  document.getElementById('statusBtn').onclick=function(){
    if(!keyEl.value.trim()){showError({message:'请先填写 Admin Key'});return;}
    fetch('/admin/account',{headers:headers()}).then(function(r){return r.json();}).then(function(j){show(j);}).catch(showError);
  };
})();
</script>
</main></body></html>`))

func (s *Server) oauthConsole(w http.ResponseWriter, _ *http.Request, _ string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = oauthPage.Execute(w, nil)
}

type oauthStartResult struct {
	AuthURL     string `json:"auth_url"`
	RedirectURI string `json:"redirect_uri"`
	ExpiresIn   int64  `json:"expires_in_seconds"`
	Reused      bool   `json:"reused,omitempty"`
}

func (s *Server) startOAuth(w http.ResponseWriter, _ *http.Request, id string) {
	s.loginMu.Lock()
	if s.loginAttempt != nil && s.now().Sub(s.loginStarted) < oauthAttemptTTL {
		result := oauthStartResult{
			AuthURL:     s.loginURL,
			RedirectURI: s.loginAttempt.RedirectURI,
			ExpiresIn:   secondsCeil(oauthAttemptTTL - s.now().Sub(s.loginStarted)),
			Reused:      true,
		}
		s.loginMu.Unlock()
		writeJSON(w, http.StatusOK, result)
		return
	}
	port := s.cfg.LoginRedirectPort
	if port == 0 {
		port = 14535
	}
	redirectURI := "http://127.0.0.1:" + strconv.Itoa(port) + "/CALLBACK_AUTH"
	authURL, attempt, err := s.account.BeginLogin(redirectURI)
	if err != nil {
		s.loginMu.Unlock()
		s.failOAuth(w, id, err)
		return
	}
	s.loginAttempt = attempt
	s.loginURL = authURL
	s.loginStarted = s.now()
	s.loginMu.Unlock()
	writeJSON(w, http.StatusOK, oauthStartResult{AuthURL: authURL, RedirectURI: redirectURI, ExpiresIn: secondsCeil(oauthAttemptTTL)})
}

type oauthCompleteRequest struct {
	CallbackURL string `json:"callback_url"`
	Code        string `json:"code"`
}

func (s *Server) completeOAuth(w http.ResponseWriter, r *http.Request, id string) {
	var body oauthCompleteRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCallbackBytes))
	if err := decoder.Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.fail(w, id, bad(http.StatusRequestEntityTooLarge, "request_too_large", "The callback body is too large.", ""))
			return
		}
		s.fail(w, id, bad(http.StatusBadRequest, "invalid_request_error", "Expected a JSON body with callback_url.", "callback_url"))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.fail(w, id, bad(http.StatusBadRequest, "invalid_request_error", "The request body must contain exactly one JSON object.", ""))
		return
	}
	raw := body.CallbackURL
	if raw == "" {
		raw = body.Code
	}

	s.loginMu.Lock()
	attempt := s.loginAttempt
	if attempt == nil {
		s.loginMu.Unlock()
		s.fail(w, id, bad(http.StatusConflict, "no_pending_login", "Start a login before submitting a callback.", ""))
		return
	}
	code, err := attempt.ParseCallback(raw)
	if err != nil {
		s.loginMu.Unlock()
		s.failOAuth(w, id, err)
		return
	}
	status, err := s.account.CompleteLogin(r.Context(), attempt, code)
	if err != nil {
		s.loginMu.Unlock()
		s.failOAuth(w, id, err)
		return
	}
	s.loginAttempt = nil
	s.loginURL = ""
	s.loginStarted = time.Time{}
	s.loginMu.Unlock()

	s.invalidateAccountCaches()
	s.log.Info("oauth_login_completed", "request_id", id, "logged_in", status.LoggedIn)
	writeJSON(w, http.StatusOK, status)
}

// invalidateAccountCaches drops model/quota caches and per-model cooldowns
// left behind by a previous Google account.
func (s *Server) invalidateAccountCaches() {
	s.models.reset()
	s.quota.reset()
	s.cacheHistory.reset()
	s.mu.Lock()
	s.globalUntil = time.Time{}
	s.modelUntil = make(map[string]time.Time)
	s.mu.Unlock()
}

// failOAuth reports a sanitized OAuth failure without echoing callback data.
func (s *Server) failOAuth(w http.ResponseWriter, id string, err error) {
	authErr, ok := err.(*auth.Error)
	if !ok {
		s.fail(w, id, bad(http.StatusBadGateway, "oauth_failed", "The OAuth flow failed.", ""))
		return
	}
	status := http.StatusBadRequest
	switch authErr.Code {
	case "invalid_redirect_uri", "no_pending_login", "state_mismatch", "missing_code", "invalid_callback", "attempt_expired":
	default:
		status = http.StatusBadGateway
	}
	e := bad(status, authErr.Code, authErr.Message, "")
	s.logError("oauth_error", id, e)
	writeJSON(w, status, e.body())
}
