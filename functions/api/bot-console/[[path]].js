// Protected management endpoints; MUST configure Cloudflare Access for /api/bot-console/*.
// Access identity is verified cryptographically at the origin; never trust website username alone.
const GUILD = '1434729354474291232';
const DAY = 86400;
const json = (obj, status=200) => Response.json(obj, {status, headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const bad = (message,status=400)=>json({ok:false,error:message},status);
function decode(input){const raw=atob(input.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-input.length%4)%4));return Uint8Array.from(raw,x=>x.charCodeAt(0));}
async function admin(req,env){
  const aud=String(env.BOT_ACCESS_AUD||'').trim();
  const team=String(env.BOT_ACCESS_TEAM_DOMAIN||'').trim().replace(/^https?:\/\//,'').replace(/\/$/,'');
  const allowed=(env.BOT_ADMIN_EMAILS||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
  if(!aud||!team||!allowed.length)throw new Error('尚未設定 Access 安全驗證');
  const token=req.headers.get('Cf-Access-Jwt-Assertion');
  if(!token) return null;
  const chunks=token.split('.');if(chunks.length!==3)return null;
  let hdr,payload;try{hdr=JSON.parse(new TextDecoder().decode(decode(chunks[0])));payload=JSON.parse(new TextDecoder().decode(decode(chunks[1])));}catch{return null;}
  const now=Math.floor(Date.now()/1000);
  if(hdr.alg!=='RS256'||!hdr.kid||!Array.isArray(payload.aud)||!payload.aud.includes(aud)||!payload.exp||payload.exp<=now||payload.nbf>now||payload.iss!==`https://${team}`)return null;
  const email=String(payload.email||'').toLowerCase();if(!allowed.includes(email))return null;
  const res=await fetch(`https://${team}/cdn-cgi/access/certs`,{cf:{cacheTtl:300,cacheEverything:true}});
  if(!res.ok)throw new Error('無法驗證 Access 公鑰');
  const obj=await res.json();const jwk=(obj.keys||[]).find(k=>k.kid===hdr.kid&&k.kty==='RSA');if(!jwk)return null;
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const sig=decode(chunks[2]), data=new TextEncoder().encode(chunks[0]+'.'+chunks[1]);
  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,data)?email:null;
}
function snowflake(s){return /^\d{17,20}$/.test(String(s||''));}
function valid(action,p){
 if(!p||typeof p!=='object'||Array.isArray(p))return '資料格式錯誤';
 const len=(x,max)=>typeof x==='string'&&x.trim().length>0&&x.length<=max;
 if(action==='panel_update'){
   if(!snowflake(p.channel_id)||!len(p.title,60)||!len(p.description,1000)||typeof p.locked!=='boolean')return '票務設定格式不正確';
   if(!Array.isArray(p.role_ids)||p.role_ids.length<1||p.role_ids.length>5||!p.role_ids.every(snowflake))return '客服身分組須指定 1～5 個';
 } else if(action==='money_create'){
   if(!['加錢','扣錢'].includes(p.kind)||!['週','月初','月底'].includes(p.cycle)||!Number.isSafeInteger(p.amount)||p.amount<1||p.amount>1000000000)return '金額或週期不合法';
   if(Number(Boolean(p.target_id))+Number(Boolean(p.role_id))!==1||!(snowflake(p.target_id||p.role_id)))return '只能指定一個成員或身分組';
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
  if(!env.BOT_PANEL_DB)return bad('尚未綁定 BOT_PANEL_DB 資料庫',503);
  let email;try{email=await admin(request,env);}catch(e){return bad('管理驗證設定錯誤：'+e.message,503);}
  if(!email)return bad('請先通過 Cloudflare Access 授權，並確認管理信箱在允許清單',401);
  const path=new URL(request.url).pathname.split('/').slice(-1)[0];
  const db=env.BOT_PANEL_DB,now=Math.floor(Date.now()/1000);
  if(request.method==='GET'){
    if(path!=='state')return bad('路由不存在',404);
    const snapshot=await db.prepare('SELECT payload,updated_at FROM bot_console_snapshot WHERE guild_id=?').bind(GUILD).first();
    const jobs=await db.prepare('SELECT id,action,operator,status,result,created_at,completed_at FROM bot_console_jobs ORDER BY created_at DESC LIMIT 40').all();
    return json({ok:true,operator:email,snapshot:snapshot?JSON.parse(snapshot.payload):null,updated_at:snapshot?.updated_at||null,jobs:jobs.results});
  }
  if(request.method!=='POST'||path!=='action')return bad('不支援的方法',405);
  const contentLength=Number(request.headers.get('content-length')||0);if(contentLength>12000)return bad('資料超過大小限制',413);
  let body;try{body=await request.json();}catch{return bad('不是有效 JSON');}
  const action=String(body.action||''),payload=body.payload||{};
  const issue=valid(action,payload);if(issue)return bad(issue);
  const id=crypto.randomUUID();
  await db.prepare('INSERT INTO bot_console_jobs(id,action,payload,operator,created_at,status) VALUES(?,?,?,?,?,?)')
    .bind(id,action,JSON.stringify(payload),email,now,'pending').run();
  return json({ok:true,id,status:'pending',notice:'已排入隊列，須等貓居 Bot 執行後才生效。'},202);
}
