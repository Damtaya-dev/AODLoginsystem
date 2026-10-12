const $=s=>document.querySelector(s),enc=new TextEncoder(),dec=new TextDecoder(),S=crypto.subtle;
const hx=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const u8=x=>new Uint8Array(x.match(/../g).map(v=>parseInt(v,16)));
const rnd=n=>hx(crypto.getRandomValues(new Uint8Array(n)));
const cat=(a,b)=>{const o=new Uint8Array(a.length+b.length);o.set(a);o.set(b,a.length);return o};
const eq=(a,b)=>{if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mem={};const ls={get(k){if(k in mem)return mem[k];try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){mem[k]=v;try{localStorage.setItem(k,v)}catch(e){}}};
let pepper,kEnc,kMac,db={users:{},log:[]},sess=null,pend=null,flash=null,dirty=false,lastBk=null,IDLE=120000;

/* ---------- Cryptography ---------- */
const hmac=async(k,d)=>S.sign('HMAC',await S.importKey('raw',k,{name:'HMAC',hash:'SHA-256'},false,['sign']),d);
async function initKeys(){let p=ls.get('vg_pepper');if(!p){p=rnd(32);ls.set('vg_pepper',p)}pepper=u8(p);
 kEnc=await S.importKey('raw',await hmac(pepper,enc.encode('enc')),'AES-GCM',false,['encrypt','decrypt']);
 kMac=new Uint8Array(await hmac(pepper,enc.encode('mac')))}
/* Confidentiality: AES-256-GCM. Integrity: HMAC-SHA-256 over iv+ciphertext (verified before decrypting). */
async function seal(o){const iv=crypto.getRandomValues(new Uint8Array(12));
 const ct=new Uint8Array(await S.encrypt({name:'AES-GCM',iv},kEnc,enc.encode(JSON.stringify(o))));
 return JSON.stringify({iv:hx(iv),ct:hx(ct),mac:hx(await hmac(kMac,cat(iv,ct))),t:Date.now()})}
async function unseal(s){const b=JSON.parse(s),iv=u8(b.iv),ct=u8(b.ct);
 if(!eq(hx(await hmac(kMac,cat(iv,ct))),b.mac))throw Error('MAC mismatch');
 return JSON.parse(dec.decode(await S.decrypt({name:'AES-GCM',iv},kEnc,ct)))}
/* Password: HMAC(pepper, password) -> PBKDF2-SHA256(per-user salt, 150k rounds) */
async function hashPw(pw,salt){const pre=await hmac(pepper,enc.encode(pw));
 const k=await S.importKey('raw',pre,'PBKDF2',false,['deriveBits']);
 return hx(await S.deriveBits({name:'PBKDF2',salt:u8(salt),iterations:150000,hash:'SHA-256'},k,256))}
/* TOTP (RFC 6238) */
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32e=b=>{let s='',o='';for(const x of b)s+=x.toString(2).padStart(8,'0');for(let i=0;i<s.length;i+=5)o+=B32[parseInt(s.slice(i,i+5).padEnd(5,'0'),2)];return o};
const b32d=t=>{let s='';for(const c of t)s+=B32.indexOf(c).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=s.length;i+=8)o.push(parseInt(s.slice(i,i+8),2));return new Uint8Array(o)};
async function hotp(sec,ctr){const k=await S.importKey('raw',b32d(sec),{name:'HMAC',hash:'SHA-1'},false,['sign']);
 const c=new DataView(new ArrayBuffer(8));c.setUint32(4,ctr);const d=new Uint8Array(await S.sign('HMAC',k,c.buffer));
 const o=d[19]&15;return String((((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3])%1e6).padStart(6,'0')}
const step=()=>Math.floor(Date.now()/30000);
async function vTotp(sec,code,last=0){for(const o of[-1,0,1]){const s=step()+o;if(s>last&&eq(await hotp(sec,s),code))return s}return -1}

/* ---------- Storage, audit log, backups ---------- */
const save=async()=>{ls.set('vg_db',await seal(db));dirty=true};
const bks=()=>{try{return JSON.parse(ls.get('vg_bk')||'[]')}catch(e){return[]}};
async function backup(why){const l=bks();l.unshift({id:rnd(4),t:Date.now(),why,blob:await seal(db)});ls.set('vg_bk',JSON.stringify(l.slice(0,5)));dirty=false;lastBk=Date.now()}
async function audit(ev,user){const prev=db.log.length?db.log[db.log.length-1].h:'0'.repeat(64),t=Date.now();
 db.log.push({t,ev,user,prev,h:hx(await S.digest('SHA-256',enc.encode(prev+t+ev+user)))});if(db.log.length>50)db.log.shift()}
async function chainOk(){for(let i=0;i<db.log.length;i++){const e=db.log[i];
 if(hx(await S.digest('SHA-256',enc.encode(e.prev+e.t+e.ev+e.user)))!==e.h)return false;if(i&&e.prev!==db.log[i-1].h)return false}return true}
async function loadDB(){const raw=ls.get('vg_db');if(!raw)return'new';
 try{db=await unseal(raw);return'ok'}catch(e){for(const b of bks()){try{db=await unseal(b.blob);await audit('Tampering detected – restored from backup','system');await save();return'restored'}catch(_){}}
 db={users:{},log:[]};return'lost'}}

/* ---------- UI helpers ---------- */
const view=(h,cls='')=>{$('#app').className=cls;$('#app').innerHTML=h;if(flash){msg(flash.t,flash.k);flash=null}};
const msg=(t,k='er')=>{const e=$('#msg');if(e)e.innerHTML=`<div class="m ${k}" role="alert">${esc(t)}</div>`};
const shell=(title,sub,body)=>`<div class="auth"><section class="brand"><div class="logo"><svg width="30" height="30" viewBox="0 0 32 32" fill="none" stroke="#e0b252" stroke-width="2.2"><circle cx="16" cy="16" r="13"/><circle cx="16" cy="16" r="5"/><path d="M16 3v6M16 23v6M3 16h6M23 16h6"/></svg>Vaultgate</div>
<div><h1>Your account, locked three ways.</h1><p>Something you know, something you have, and everything encrypted at rest.</p></div>
<ul><li>Salted and peppered password hashing</li><li>Two-factor codes that change every 30 seconds</li><li>Encrypted storage with tamper detection</li><li>Automatic backups, one click restore</li></ul></section>
<section class="side"><div class="box"><h2>${title}</h2><p class="sub">${sub}</p><div id="msg"></div>${body}</div></section></div>`;
const strength=p=>{let s=0;if(p.length>=10)s++;if(p.length>=14)s++;if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++;if(/\d/.test(p))s++;if(/[^\w\s]/.test(p))s++;return s};
function meter(){const s=strength($('#p').value),b=$('#sb');b.style.width=s*20+'%';b.style.background=s<3?'var(--er)':s<4?'#d99a1a':'var(--ok)';$('#sl').textContent=['Too weak','Too weak','Weak','Fair','Strong','Excellent'][s]}

/* ---------- Views ---------- */
const loginV=()=>view(shell('Sign in','Enter your username and password to continue.',
`<form onsubmit="doLogin(event)" autocomplete="off"><label for="u">Username</label><input id="u" required autofocus autocomplete="username">
<label for="p">Password</label><input id="p" type="password" required autocomplete="current-password"><button class="btn">Continue</button></form>
<p class="alt">New here? <button class="lnk" onclick="regV()">Create an account</button></p>`));
const regV=()=>view(shell('Create account',Object.keys(db.users).length?'Choose a username and a strong password.':'The first account becomes the administrator.',
`<form onsubmit="doReg(event)" autocomplete="off"><label for="u">Username</label><input id="u" required pattern="[a-zA-Z0-9_.\\-]{3,20}" title="3–20 letters, numbers, . _ -">
<div class="hint">3–20 letters, numbers, dot, dash or underscore.</div>
<label for="p">Password</label><input id="p" type="password" required minlength="10" oninput="meter()" autocomplete="new-password">
<div class="bar"><i id="sb"></i></div><div class="hint" id="sl">Use at least 10 characters.</div>
<label for="p2">Confirm password</label><input id="p2" type="password" required autocomplete="new-password"><button class="btn">Set up two-factor</button></form>
<p class="alt">Already registered? <button class="lnk" onclick="loginV()">Sign in</button></p>`));
function setupV(){const g=pend.secret.match(/.{4}/g).join(' ');
 view(shell('Add your authenticator','Enter this key in Google Authenticator, Authy or any TOTP app, then type the 6-digit code it shows.',
`<div class="m in"><div class="mono">${g}</div></div>
<div class="dial"><div class="ring"><svg width="76" height="76"><circle cx="38" cy="38" r="33" fill="none" stroke="var(--ln)" stroke-width="6"/><circle id="rg" cx="38" cy="38" r="33" fill="none" stroke="var(--ac)" stroke-width="6" stroke-linecap="round" stroke-dasharray="207.3" stroke-dashoffset="0"/></svg><b id="sec"></b></div>
<div><div class="hint">Demo code (no app handy?)</div><div class="code" id="demo">······</div></div></div>
<form onsubmit="doSetup(event)" autocomplete="off"><label for="c">6-digit code</label><input id="c" inputmode="numeric" pattern="\\d{6}" maxlength="6" required autofocus><button class="btn">Verify and create account</button></form>
<p class="alt"><button class="lnk" onclick="regV()">Cancel</button></p>`))}
const otpV=()=>view(shell('Two-factor check','Open your authenticator app and enter the current code.',
`<form onsubmit="doOtp(event)" autocomplete="off"><label for="c">6-digit code</label><input id="c" inputmode="numeric" pattern="\\d{6}" maxlength="6" required autofocus autocomplete="one-time-code"><button class="btn">Verify and sign in</button></form>
<p class="alt"><button class="lnk" onclick="pend=null;loginV()">Back to sign in</button> · <button class="lnk" onclick="demoCode()">Show demo code</button></p><div class="hint" id="dc" style="text-align:center"></div>`));
async function demoCode(){$('#dc').textContent='Demo only (no server): '+await hotp(db.users[pend.un].secret,step())}

/* ---------- Auth actions ---------- */
async function doReg(e){e.preventDefault();const un=$('#u').value.trim().toLowerCase(),pw=$('#p').value;
 if(pw!==$('#p2').value)return msg('Passwords do not match.');if(strength(pw)<3)return msg('Password is too weak. Add length, numbers or symbols.');
 if(db.users[un])return msg('That username is taken. Pick another.');
 const salt=rnd(16);pend={un,salt,hash:await hashPw(pw,salt),secret:b32e(crypto.getRandomValues(new Uint8Array(20))),role:Object.keys(db.users).length?'user':'admin'};setupV()}
async function doSetup(e){e.preventDefault();const s=await vTotp(pend.secret,$('#c').value.trim());
 if(s<0)return msg('That code is not valid. Check your app and try again.');
 const{un,salt,hash,secret,role}=pend;db.users[un]={un,salt,hash,secret,role,fail:0,strikes:0,lock:0,last:s,created:Date.now()};
 await audit('Account created ('+role+')',un);await save();await backup('new account');pend=null;flash={t:'Account created. Sign in to continue.',k:'ok'};loginV()}
async function strike(u,why){u.fail++;await audit(why,u.un);if(u.fail>=5){u.lock=Date.now()+30000*2**Math.min(u.strikes++,6);u.fail=0;await audit('Account locked',u.un)}await save()}
const lockLeft=u=>Math.ceil((u.lock-Date.now())/1000);
async function doLogin(e){e.preventDefault();const un=$('#u').value.trim().toLowerCase(),pw=$('#p').value,u=db.users[un];
 if(u&&u.lock>Date.now())return msg(`Too many attempts. Try again in ${lockLeft(u)} seconds.`);
 const h=await hashPw(pw,u?u.salt:'00'.repeat(16));
 if(!u||!eq(h,u.hash)){if(u)await strike(u,'Failed password');return msg('Username or password is incorrect.')}
 pend={un};otpV()}
async function doOtp(e){e.preventDefault();const u=db.users[pend.un];
 if(u.lock>Date.now())return msg(`Account locked. Try again in ${lockLeft(u)} seconds.`);
 const s=await vTotp(u.secret,$('#c').value.trim(),u.last);
 if(s<0){await strike(u,'Failed 2FA code');return msg('That code is not valid or was already used.')}
 u.fail=0;u.strikes=0;u.last=s;sess={un:u.un,role:u.role,act:Date.now()};pend=null;await audit('Signed in',u.un);await save();dashV()}
async function logout(why){if(sess){await audit(why||'Signed out',sess.un);await save();if(dirty)await backup('on sign-out')}sess=null;flash=why?{t:why,k:'in'}:null;loginV()}

/* ---------- Dashboard ---------- */
async function dashV(){if(!sess)return;const u=db.users[sess.un],ok=await chainOk(),adm=sess.role==='admin',f=t=>new Date(t).toLocaleString([], {dateStyle:'short',timeStyle:'medium'});
 view(`<div class="dash"><div class="top"><div><h2>Welcome, ${esc(u.un)}</h2><span class="pill">${esc(u.role)} access</span></div><button class="btn sm ghost" onclick="logout()">Sign out</button></div><div id="msg"></div>
<div class="grid"><div class="card hero"><h3>Session</h3><div class="big" id="cd">2:00</div><div class="hint" style="color:#9fc3c0">Idle time left. Any activity resets it.</div></div>
<div class="card"><h3>Protection in place</h3>
<div class="row ck">Password: peppered, salted, PBKDF2 ×150,000</div><div class="row ck">Two-factor: TOTP, codes can’t be reused</div>
<div class="row ck">Storage: AES-256-GCM encrypted, HMAC-SHA-256 verified</div><div class="row ck">Lockout after 5 misses, growing delay</div>
<div class="row ck">Access: role based, ${adm?'you can manage users':'standard users see only their own data'}</div>
<div class="row"><span>Your salt</span><span class="mono">${u.salt.slice(0,16)}…</span></div><div class="row"><span>Your hash</span><span class="mono">${u.hash.slice(0,16)}…</span></div></div>
<div class="card"><h3>Backups</h3><div class="hint" style="margin-bottom:8px">Automatic every 30 s after changes. Newest 5 kept, each encrypted and signed.</div><div id="bk">${bkHtml(f)}</div>
<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button class="btn sm" onclick="manBk()">Back up now</button>${adm?'<button class="btn sm ghost" onclick="tamper()">Simulate tampering</button>':''}</div></div>
<div class="card"><h3>Audit log <span class="pill" style="color:${ok?'var(--ok)':'var(--er)'}">${ok?'chain verified':'chain broken'}</span></h3>
${db.log.slice(-7).reverse().map(e=>`<div class="row"><span>${esc(e.ev)} <span class="hint">${esc(e.user)}</span></span><span class="hint">${f(e.t)}</span></div>`).join('')}</div>
${adm?`<div class="card" style="grid-column:1/-1"><h3>Users (admin only)</h3><div class="scroll"><table><tr><th>User</th><th>Role</th><th>Status</th><th></th></tr>${Object.values(db.users).map(x=>`<tr><td>${esc(x.un)}</td><td>${esc(x.role)}</td><td>${x.lock>Date.now()?'Locked '+lockLeft(x)+'s':'Active'}</td><td>${x.lock>Date.now()?`<button class="btn sm ghost" onclick="unlock('${esc(x.un)}')">Unlock</button>`:''}</td></tr>`).join('')}</table></div></div>`:''}
</div></div>`);tick()}
const bkHtml=f=>bks().map(b=>`<div class="row"><span>${f(b.t)} <span class="hint">${esc(b.why)}</span></span><button class="btn sm ghost" onclick="restore('${b.id}')">Restore</button></div>`).join('')||'<div class="hint">No backups yet.</div>';
async function manBk(){await backup('manual');dashV();msg('Backup saved.','ok')}
async function restore(id){const b=bks().find(x=>x.id===id);try{db=await unseal(b.blob)}catch(e){return msg('Backup failed its integrity check and was not restored.')}
 await audit('Restored backup','system');await save();sess=null;flash={t:'Backup restored. Please sign in again.',k:'ok'};loginV()}
async function unlock(un){if(sess?.role!=='admin')return;const u=db.users[un];u.lock=0;u.fail=0;await audit('Unlocked by admin',un);await save();dashV()}
async function tamper(){await backup('before tamper test');const b=JSON.parse(ls.get('vg_db'));b.ct=(b.ct[0]==='a'?'b':'a')+b.ct.slice(1);ls.set('vg_db',JSON.stringify(b));
 try{await unseal(ls.get('vg_db'))}catch(e){const r=await loadDB();sess=null;flash={t:'Tampering detected: the stored data failed its integrity check, so it was restored from the latest backup. Sign in again.',k:'in'};loginV()}}

/* ---------- Timers ---------- */
async function tick(){const now=Date.now();
 if(sess){const left=IDLE-(now-sess.act);if(left<=0)return logout('Signed out after 2 minutes of inactivity.');const c=$('#cd');if(c)c.textContent=Math.floor(left/60000)+':'+String(Math.floor(left/1000)%60).padStart(2,'0')}
 const d=$('#demo');if(d&&pend?.secret){d.textContent=await hotp(pend.secret,step());const r=30-(now/1000%30);$('#sec').textContent=Math.ceil(r);$('#rg').style.strokeDashoffset=207.3*(1-r/30)}}
setInterval(tick,1000);
setInterval(async()=>{if(dirty){await backup('auto');if(sess&&$('#bk'))$('#bk').innerHTML=bkHtml(t=>new Date(t).toLocaleString([], {dateStyle:'short',timeStyle:'medium'}))}},30000);
['click','keydown','mousemove','touchstart'].forEach(ev=>addEventListener(ev,()=>{if(sess)sess.act=Date.now()},{passive:true}));
$('#tg').onclick=()=>{const r=document.documentElement,d=r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme:dark)').matches;r.dataset.theme=d?'light':'dark'};

(async()=>{await initKeys();const s=await loadDB();
 if(s==='restored')flash={t:'Stored data failed its integrity check and was restored from backup.',k:'in'};
 if(s==='lost')flash={t:'Stored data was damaged and no valid backup exists. Starting fresh.',k:'er'};
 Object.keys(db.users).length?loginV():regV()})();
