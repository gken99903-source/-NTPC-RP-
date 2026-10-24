// Dedicated machine-to-machine endpoint. No admin Access needed; verifies a strong private token.
const GUILD='1434729354474291232';
const json=(obj,status=200)=>Response.json(obj,{status,headers:{'cache-control':'no-store'}});
async function valid(req,env){
 const expected=String(env.BOT_PANEL_SYNC_TOKEN||'');if(expected.length<32)return false;
 const got=req.headers.get('authorization')||'';
 const expectedBytes=new TextEncoder().encode('Bearer '+expected),actual=new TextEncoder().encode(got);
 if(expectedBytes.length!==actual.length)return false;
 // Compare hashed values in constant-time primitive; never store secrets in GitHub.
 const [a,b]=await Promise.all([crypto.subtle.digest('SHA-256',expectedBytes),crypto.subtle.digest('SHA-256',actual)]);
 return [...new Uint8Array(a)].every((v,i)=>v===new Uint8Array(b)[i]);
}
export async function onRequest({request,env}){
 if(!env.BOT_PANEL_DB)return json({ok:false,error:'Database not bound'},503);
 if(!await valid(request,env))return json({ok:false,error:'Unauthorized'},401);
 const db=env.BOT_PANEL_DB,part=new URL(request.url).pathname.split('/').pop(),now=Math.floor(Date.now()/1000);
 if(request.method==='GET'&&part==='poll'){
   await db.prepare("UPDATE bot_console_jobs SET status='pending',claimed_at=NULL WHERE status='processing' AND claimed_at<?").bind(now-180).run();
   const r=await db.prepare("SELECT id,action,payload,operator,created_at FROM bot_console_jobs WHERE status='pending' ORDER BY created_at LIMIT 10").all();
   return json({ok:true,jobs:r.results.map(j=>({...j,payload:JSON.parse(j.payload)}))});
 }
 if(request.method!=='POST')return json({ok:false,error:'Method not allowed'},405);
 let body;try{body=await request.json();}catch{return json({ok:false,error:'Invalid JSON'},400);}
 if(part==='claim'){
   const result=await db.prepare("UPDATE bot_console_jobs SET status='processing',claimed_at=? WHERE id=? AND status='pending'").bind(now,String(body.id)).run();
   return json({ok:true,claimed:result.meta.changes===1});
 }
 if(part==='complete'){
   if(!['done','failed'].includes(body.status))return json({ok:false,error:'Invalid status'},400);
   await db.prepare("UPDATE bot_console_jobs SET status=?,result=?,completed_at=? WHERE id=? AND status='processing'")
     .bind(body.status,String(body.result||'').slice(0,1200),now,String(body.id)).run();
   await db.prepare('DELETE FROM bot_console_jobs WHERE created_at<?').bind(now-30*86400).run();
   return json({ok:true});
 }
 if(part==='snapshot'){
   const state=body.state;
   if(!state||typeof state!=='object'||JSON.stringify(state).length>60000)return json({ok:false,error:'Invalid snapshot'},400);
   await db.prepare('INSERT INTO bot_console_snapshot(guild_id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(guild_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at')
     .bind(GUILD,JSON.stringify(state),now).run();
   return json({ok:true});
 }
 return json({ok:false,error:'Not found'},404);
}
