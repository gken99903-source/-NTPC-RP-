// Protected management endpoints; independent administrator API key authentication.
// No Cloudflare Access required. Never trust website username/sessionStorage alone.
const GUILD = '1434729354474291232';
const DAY = 86400;
const json = (obj, status=200) => Response.json(obj, {status, headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const bad = (message,status=400)=>json({ok:false,error:message},status);
// Each administrator has an independent 256-bit random key. Store only SHA-256 key hashes
// in the Pages secret BOT_ADMIN_KEYS, as a JSON object {"website_account":"hex hash"}.
// Existing website sessionStorage is NOT a trusted authorization credential.
async function admin(req,env){
  const raw=String(env.BOT_ADMIN_KEYS||'');
  if(!raw)throw new Error('尚未設定 BOT_ADMIN_KEYS 管理員密鑰雜湊');
  let keys;try{keys=JSON.parse(raw);}catch{throw new Error('BOT_ADMIN_KEYS 必須為 JSON 物件');}
  if(!keys||typeof keys!=='object'||Array.isArray(keys))throw new Error('BOT_ADMIN_KEYS 格式錯誤');
  const header=req.headers.get('authorization')||'';
  if(!header.startsWith('Bearer '))return null;
  const value=header.slice(7);
  const cut=value.indexOf(':');if(cut<1)return null;
  const account=value.slice(0,cut).trim().toLowerCase();const token=value.slice(cut+1);
  if(account.length<1||account.length>80||!/^[\p{L}\p{N}_.-]+$/u.test(account)||!/^[a-f0-9]{64}$/.test(token))return null;
  const expected=String(Object.entries(keys).find(([k])=>k.toLowerCase()===account)?.[1]||'').toLowerCase();
  if(!/^[a-f0-9]{64}$/.test(expected))return null;
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token));
  const actual=Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,'0')).join('');
  let difference=0;for(let i=0;i<64;i++)difference|=actual.charCodeAt(i)^expected.charCodeAt(i);
  return difference===0?account:null;
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
  let account;try{account=await admin(request,env);}catch(e){return bad('管理驗證設定錯誤：'+e.message,503);}
  if(!account)return bad('網站帳號或專用密鑰驗證失敗',401);
  // Reject cross-site requests even when an administrator accidentally loads a malicious page.
  const origin=request.headers.get('origin');
  if(origin && origin!==new URL(request.url).origin)return bad('跨來源請求遭拒',403);
  const path=new URL(request.url).pathname.split('/').slice(-1)[0];
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
