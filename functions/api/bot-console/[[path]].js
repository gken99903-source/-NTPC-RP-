// Protected management endpoints; independent administrator API key authentication.
// No Cloudflare Access required. Never trust website username/sessionStorage alone.
const GUILD = '1434729354474291232';
const DAY = 86400;
const json = (obj, status=200) => Response.json(obj, {status, headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const bad = (message,status=400)=>json({ok:false,error:message},status);
// Each administrator has an independent 256-bit random key. Store only SHA-256 key hashes
// in the Pages secret BOT_ADMIN_KEYS, as a JSON object {"website_account":"hex hash"}.
// Existing website sessionStorage is NOT a trusted authorization credential.
const BOT_COOKIE='ntpc_bot_admin_v107';
const textEncoder=new TextEncoder();
const toHex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
const fromHex=value=>Uint8Array.from(value.match(/.{2}/g)||[],x=>parseInt(x,16));
function equalBytes(a,b){
  if(a.length!==b.length)return false;
  let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0;
}
function originAllowed(req){
  const origin=req.headers.get('origin');
  if(origin&&origin!==new URL(req.url).origin)return false;
  const site=req.headers.get('sec-fetch-site');
  return !site||site==='same-origin'||site==='none';
}
function getCookie(req,name){
  const cookies=(req.headers.get('cookie')||'').split(';');
  for(const c of cookies){let t=c.trim();if(t.startsWith(name+'='))return t.slice(name.length+1);}
  return '';
}
async function signingKey(env){
  const secret=String(env.BOT_CONSOLE_SESSION_SECRET||'');
  if(secret.length<32)throw new Error('尚未設定至少 32 字元的 BOT_CONSOLE_SESSION_SECRET');
  return crypto.subtle.importKey('raw',textEncoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
async function signCookie(payload,env){
  const value=toHex(textEncoder.encode(JSON.stringify(payload)));
  const mac=toHex(new Uint8Array(await crypto.subtle.sign('HMAC',await signingKey(env),textEncoder.encode(value))));
  return value+'.'+mac;
}
async function sessionAccount(req,env){
  const token=getCookie(req,BOT_COOKIE);
  if(token.length<140||token.length>1200)return null;
  const pair=token.split('.');if(pair.length!==2||!/^[a-f0-9]+$/.test(pair[0])||!/^[a-f0-9]{64}$/.test(pair[1])||pair[0].length%2)return null;
  const good=await crypto.subtle.verify('HMAC',await signingKey(env),fromHex(pair[1]),textEncoder.encode(pair[0]));
  if(!good)return null;
  let payload;try{payload=JSON.parse(new TextDecoder().decode(fromHex(pair[0])));}catch{return null;}
  const now=Math.floor(Date.now()/1000);
  if(payload.v!==1||payload.account!=='dsuensx'||!Number.isInteger(payload.iat)||!Number.isInteger(payload.exp)||payload.iat>now+60||payload.exp<=now||payload.exp>payload.iat+7200)return null;
  return payload.account;
}
async function verifyDsuensxPassword(password,env){
  // Format: 32-byte random salt (hex):iterations:PBKDF2-SHA256 32-byte digest (hex).
  const parts=String(env.BOT_DSUENSX_PASSWORD_PBKDF2||'').split(':');
  if(parts.length!==3||!/^[a-f0-9]{64}$/i.test(parts[0])||!/^[0-9]{6,8}$/.test(parts[1])||!/^[a-f0-9]{64}$/i.test(parts[2]))
    throw new Error('尚未設定有效 BOT_DSUENSX_PASSWORD_PBKDF2');
  const iters=Number(parts[1]);if(iters<200000||iters>1000000)throw new Error('PBKDF2 次數必須介於 200000～1000000');
  if(typeof password!=='string'||password.length<1||password.length>256)return false;
  const key=await crypto.subtle.importKey('raw',textEncoder.encode(password),'PBKDF2',false,['deriveBits']);
  const computed=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:fromHex(parts[0]),iterations:iters,hash:'SHA-256'},key,256));
  return equalBytes(computed,fromHex(parts[2]));
}
async function legacyAdmin(req,env){
  const raw=String(env.BOT_ADMIN_KEYS||'');
  if(!raw)return null;
  let keys;try{keys=JSON.parse(raw);}catch{throw new Error('BOT_ADMIN_KEYS 必須為 JSON 物件');}
  if(!keys||typeof keys!=='object'||Array.isArray(keys))throw new Error('BOT_ADMIN_KEYS 格式錯誤');
  const header=req.headers.get('authorization')||'';
  if(!header.startsWith('Bearer '))return null;
  const value=header.slice(7);const cut=value.indexOf(':');if(cut<1)return null;
  const account=value.slice(0,cut).trim().toLowerCase();const token=value.slice(cut+1);
  // Dsuensx 不能用前端 Bearer 金鑰冒認，必須出示伺服器核發的簽章工作階段。
  if(account==='dsuensx'||account.length<1||account.length>80||!/^[\p{L}\p{N}_.-]+$/u.test(account)||!/^[a-f0-9]{64}$/.test(token))return null;
  const expected=String(Object.entries(keys).find(([k])=>k.toLowerCase()===account)?.[1]||'').toLowerCase();
  if(!/^[a-f0-9]{64}$/.test(expected))return null;
  const actual=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',textEncoder.encode(token))));
  return equalBytes(fromHex(actual),fromHex(expected))?account:null;
}
async function admin(req,env){
  // If a caller explicitly supplies a key, validate only that account. Do not let a
  // stale Dsuensx browser Cookie override a different administrator's Bearer key.
  if(req.headers.get('authorization'))return legacyAdmin(req,env);
  const cookieAccount=await sessionAccount(req,env);
  if(cookieAccount)return cookieAccount;
  return null;
}
function cookieHeader(token,maxAge){return BOT_COOKIE+'='+token+'; Path=/api/bot-console; Max-Age='+maxAge+'; HttpOnly; Secure; SameSite=Strict';}
async function sessionEndpoint(req,env){
  if(!originAllowed(req))return bad('跨來源請求遭拒',403);
  if(req.method==='DELETE')return new Response(JSON.stringify({ok:true}),{headers:{'content-type':'application/json','cache-control':'no-store','set-cookie':cookieHeader('',0)}});
  if(req.method!=='POST')return bad('不支援的方法',405);
  const contentLength=Number(req.headers.get('content-length')||0);if(contentLength>2000)return bad('登入資料超過限制',413);
  if(!(req.headers.get('content-type')||'').toLowerCase().includes('application/json'))return bad('請提供 JSON',415);
  let data;try{data=await req.json();}catch{return bad('無效 JSON');}
  if(String(data?.account||'').trim().toLowerCase()!=='dsuensx')return bad('這個登入方式只提供指定帳號使用',403);
  let verified=false;
  try{verified=await verifyDsuensxPassword(data?.password,env);}catch(e){return bad('Dsuensx 自動驗證設定錯誤：'+e.message,503);}
  if(!verified)return bad('帳號密碼驗證失敗',401);
  const now=Math.floor(Date.now()/1000);
  let token;try{token=await signCookie({v:1,account:'dsuensx',iat:now,exp:now+7200},env);}catch(e){return bad('工作階段設定錯誤：'+e.message,503);}
  return new Response(JSON.stringify({ok:true,operator:'dsuensx'}),{headers:{'content-type':'application/json','cache-control':'no-store','set-cookie':cookieHeader(token,7200)}});
}
function snowflake(s){return /^\d{17,20}$/.test(String(s||''));}
function valid(action,p){
 if(!p||typeof p!=='object'||Array.isArray(p))return '資料格式錯誤';
 const len=(x,max)=>typeof x==='string'&&x.trim().length>0&&x.length<=max;
 if(action==='site_subject_upsert'){
   if(!/^[a-z0-9_-]{6,50}$/.test(String(p.id||''))||!len(p.name,70)||!len(p.intro,950)||typeof p.enabled!=='boolean')return '主題名稱或說明不正確';
   if(!Array.isArray(p.role_ids)||p.role_ids.length<1||p.role_ids.length>5||!p.role_ids.every(snowflake)||new Set(p.role_ids).size!==p.role_ids.length)return '請指定 1～5 個有效客服身分組';
   if(p.category_id&&!snowflake(p.category_id))return '分類 ID 格式不正確';
   if(!Array.isArray(p.questions)||p.questions.length>4)return '主題事前問題可為 0～4 題';
   const labels=new Set();
   for(const q of p.questions){
     if(!len(q.label,45)||typeof q.required!=='boolean'||typeof q.paragraph!=='boolean'||labels.has(q.label))return '問題標題有空白、重複或長度錯誤';
     labels.add(q.label);
   }
 }else if(action==='site_panel_publish'){
   if(!snowflake(p.channel_id)||!len(p.title,100)||!len(p.description,1500)||!len(p.placeholder,100))return '面板頻道、標題或說明格式錯誤';
   if(!Array.isArray(p.topic_ids)||p.topic_ids.length<1||p.topic_ids.length>20||!p.topic_ids.every(x=>/^[a-z0-9_-]{6,50}$/.test(String(x)))||new Set(p.topic_ids).size!==p.topic_ids.length)return '請選擇 1～20 個不同主題';
 }else if(action==='panel_update'){
   if(!snowflake(p.channel_id)||!len(p.title,60)||!len(p.description,1000)||typeof p.locked!=='boolean')return '票務設定格式不正確';
   if(!Array.isArray(p.role_ids)||p.role_ids.length<1||p.role_ids.length>5||!p.role_ids.every(snowflake))return '客服身分組須指定 1～5 個';
 } else if(action==='money_create'||action==='money_update'){
   if(!['加錢','扣錢'].includes(p.kind)||!['週','月初','月底'].includes(p.cycle)||!Number.isSafeInteger(p.amount)||p.amount<1||p.amount>1000000000)return '金額或週期不合法';
   if(Number(Boolean(p.target_id))+Number(Boolean(p.role_id))!==1||!(snowflake(p.target_id||p.role_id)))return '只能指定一個成員或身分組';
   if(action==='money_update'&&(!Number.isSafeInteger(p.job_id)||p.job_id<1))return '要修改的排程編號不正確';
 } else if(action==='money_cancel'){
   if(!Number.isSafeInteger(p.job_id)||p.job_id<=0)return '排程編號不正確';
 } else if(action==='message_send'){
   if(!snowflake(p.channel_id)||!len(p.content,2000)||!['normal','vote','settlement'].includes(p.template_kind||'normal'))return '訊息內容或頻道錯誤';
   if(p.template_kind==='vote'||p.template_kind==='settlement'){
     if(String(p.channel_id)!=='1435222492481323113')return '此模板只能發在指定投票頻道';
   }
 } else if(action==='message_edit'){
   if(!snowflake(p.message_id)||!len(p.content,2000))return '訊息編號或內容錯誤';
 } else return '不支援此操作';
 return null;
}
export async function onRequest({request,env}){
  const path=new URL(request.url).pathname.split('/').slice(-1)[0];
  if(path==='session')return sessionEndpoint(request,env);
  if(!env.BOT_PANEL_DB)return bad('尚未綁定 BOT_PANEL_DB 資料庫',503);
  let account;try{account=await admin(request,env);}catch(e){return bad('管理驗證設定錯誤：'+e.message,503);}
  if(!account)return bad('網站帳號或專用密鑰驗證失敗',401);
  // Reject cross-site requests even when an administrator accidentally loads a malicious page.
  if(!originAllowed(request))return bad('跨來源請求遭拒',403);
  const db=env.BOT_PANEL_DB,now=Math.floor(Date.now()/1000);
  if(request.method==='GET'){
    if(path!=='state')return bad('路由不存在',404);
    const snapshot=await db.prepare('SELECT payload,updated_at FROM bot_console_snapshot WHERE guild_id=?').bind(GUILD).first();
    const jobs=await db.prepare('SELECT id,action,operator,status,result,created_at,completed_at FROM bot_console_jobs ORDER BY created_at DESC LIMIT 40').all();
    return json({ok:true,operator:account,snapshot:snapshot?JSON.parse(snapshot.payload):null,updated_at:snapshot?.updated_at||null,jobs:jobs.results});
  }
  if(request.method!=='POST'||path!=='action')return bad('不支援的方法',405);
  const contentLength=Number(request.headers.get('content-length')||0);if(contentLength>12000)return bad('資料超過大小限制',413);
  let body;try{body=await request.json();}catch{return bad('不是有效 JSON');}
  const action=String(body.action||''),payload=body.payload||{};
  const issue=valid(action,payload);if(issue)return bad(issue);
  const id=crypto.randomUUID();
  await db.prepare('INSERT INTO bot_console_jobs(id,action,payload,operator,created_at,status) VALUES(?,?,?,?,?,?)')
    .bind(id,action,JSON.stringify(payload),account,now,'pending').run();
  return json({ok:true,id,status:'pending',notice:'已排入隊列，須等貓居 Bot 執行後才生效。'},202);
}
