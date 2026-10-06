type AppCode = 'ca' | 'rc' | 'sc';
type Role = 'Overseer' | 'Assistant' | 'Keyman' | 'Captain';

interface EventRow {
  id:string; app:AppCode; name:string; start_date:string; end_date:string; status:string; structure_mode:'Simple'|'Departmental'|'Full';
  entry_enabled:number; entry_token_hash:string|null; schedule_locked_at:string|null; created_at:string; updated_at:string;
}
interface Env {
  DB:D1Database;
  GMAIL_CLIENT_ID?:string; GMAIL_CLIENT_SECRET?:string; GMAIL_REFRESH_TOKEN?:string; GMAIL_FROM?:string;
}

interface VolunteerRow {
  id:string; event_id:string; first_name:string; last_name:string; gender:'Male'|'Female';
  email:string|null; phone:string|null; family:string|null; active:number; created_at:string; updated_at:string;
  roles?: string[];
}

// Cloudflare Access validation for protected OurPortal routes.
// Public confirmation links remain token-scoped and do not require Access.
const ACCESS_TEAM_DOMAIN='https://long-resonance-efd5.cloudflareaccess.com';
const ACCESS_AUD='65faf2e3c4e825912390bc3dcb03f662f9f46b62342c0a39d29b95b12e389142';
let accessKeysCache:{expires:number;keys:JsonWebKey[]}|null=null;

function b64urlBytes(v:string){
 const b64=v.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-v.length%4)%4);
 const raw=atob(b64),a=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)a[i]=raw.charCodeAt(i);return a;
}
async function accessKeys(){
 const now=Date.now();if(accessKeysCache&&accessKeysCache.expires>now)return accessKeysCache.keys;
 const r=await fetch(`${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`);
 if(!r.ok)throw new Error('Unable to load Cloudflare Access signing keys');
 const j=await r.json() as {keys?:JsonWebKey[]};if(!Array.isArray(j.keys)||!j.keys.length)throw new Error('Cloudflare Access signing keys unavailable');
 accessKeysCache={expires:now+300000,keys:j.keys};return j.keys;
}
async function validateAccess(request:Request){
 const token=request.headers.get('Cf-Access-Jwt-Assertion');if(!token)return false;
 const parts=token.split('.');if(parts.length!==3)return false;
 try{
  const header=JSON.parse(new TextDecoder().decode(b64urlBytes(parts[0]))) as {kid?:string;alg?:string};
  const payload=JSON.parse(new TextDecoder().decode(b64urlBytes(parts[1]))) as {iss?:string;aud?:string|string[];exp?:number;nbf?:number};
  if(header.alg!=='RS256'||!header.kid)return false;
  if(payload.iss!==ACCESS_TEAM_DOMAIN)return false;
  const aud=Array.isArray(payload.aud)?payload.aud:[payload.aud];if(!aud.includes(ACCESS_AUD))return false;
  const now=Math.floor(Date.now()/1000);if(typeof payload.exp!=='number'||payload.exp<=now)return false;
  if(typeof payload.nbf==='number'&&payload.nbf>now+60)return false;
  const jwk=(await accessKeys()).find(k=>(k as any).kid===header.kid);if(!jwk)return false;
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,b64urlBytes(parts[2]),new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
 }catch{return false}
}
function needsAccess(path:string){
 // Public token/code-scoped volunteer routes: /entry/*, /api/entry/*, /e/* and /api/e/*.
 // Administrator event applications and event APIs remain protected by Cloudflare Access.
 return /^\/(?:ca|rc|sc)(?:\/|$)/.test(path)||path==='/api/me'||/^\/api\/events(?:\/|$)/.test(path);
}

function accessEmail(request:Request){
 const token=request.headers.get('Cf-Access-Jwt-Assertion');if(!token)return '';
 try{const p=token.split('.')[1];if(!p)return '';const j=JSON.parse(new TextDecoder().decode(b64urlBytes(p))) as {email?:string};return clean(j.email).toLowerCase()}catch{return ''}
}
async function isFullAdmin(env:Env,email:string){if(!email)return false;return !!(await env.DB.prepare(`SELECT 1 ok FROM app_admins WHERE lower(email)=lower(?) AND active=1`).bind(email).first())}
async function isEventAdmin(env:Env,eventId:string,email:string){if(await isFullAdmin(env,email))return true;return !!(await env.DB.prepare(`SELECT 1 ok FROM app_permissions WHERE event_id=? AND lower(email)=lower(?) AND COALESCE(role,scope)='Event Admin'`).bind(eventId,email).first())}
async function hasEventPermission(env:Env,eventId:string,email:string){
 if(await isFullAdmin(env,email))return true;
 return !!(await env.DB.prepare(`SELECT 1 ok FROM app_permissions WHERE event_id=? AND lower(email)=lower(?) LIMIT 1`).bind(eventId,email).first());
}
async function permittedDepartments(env:Env,eventId:string,email:string){
 if(await isEventAdmin(env,eventId,email)){const r=await env.DB.prepare(`SELECT id FROM departments WHERE event_id=?`).bind(eventId).all<{id:string}>();return new Set(r.results.map(x=>x.id));}
 const r=await env.DB.prepare(`SELECT department_id,scope_ref_id,COALESCE(role,scope) role FROM app_permissions WHERE event_id=? AND lower(email)=lower(?)`).bind(eventId,email).all<any>();
 const out=new Set<string>();
 for(const x of r.results){
  if(['Department Overseer','Department Assistant'].includes(x.role)&&x.department_id)out.add(x.department_id);
  if(x.role==='Committee'&&x.scope_ref_id){const d=await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND committee_node_id=?`).bind(eventId,x.scope_ref_id).all<{id:string}>();for(const z of d.results)out.add(z.id);}
 }
 return out;
}
async function canAccessDepartment(env:Env,eventId:string,email:string,departmentId:string){return (await permittedDepartments(env,eventId,email)).has(departmentId)}
async function accessContext(env:Env,eventId:string,email:string){
 const full=await isFullAdmin(env,email),eventAdmin=await isEventAdmin(env,eventId,email);
 const r=await env.DB.prepare(`SELECT id,email,department_id,scope_ref_id,COALESCE(role,scope) role FROM app_permissions WHERE event_id=? AND lower(email)=lower(?) ORDER BY created_at`).bind(eventId,email).all<any>();
 const roles=r.results.map(x=>({id:x.id,role:x.role,department_id:x.department_id||null,scope_ref_id:x.scope_ref_id||null}));
 return {full_admin:full,event_admin:eventAdmin,roles};
}
async function accessData(req:Request,env:Env,eventId:string){return json({ok:true,...await accessContext(env,eventId,accessEmail(req))})}
async function volunteerPermission(env:Env,eventId:string,email:string){return env.DB.prepare(`SELECT scope_ref_id volunteer_id FROM app_permissions WHERE event_id=? AND lower(email)=lower(?) AND COALESCE(role,scope)='Volunteer' ORDER BY created_at LIMIT 1`).bind(eventId,email).first<{volunteer_id:string}>()}
async function mySchedule(req:Request,env:Env,eventId:string){
 const email=accessEmail(req),vp=await volunteerPermission(env,eventId,email);if(!vp?.volunteer_id)return json({ok:false,error:'Volunteer access is not assigned to this account.'},403);
 const v=await env.DB.prepare(`SELECT id,first_name,last_name,email,phone FROM volunteers WHERE id=? AND event_id=?`).bind(vp.volunteer_id,eventId).first<any>();if(!v)return nf('Volunteer record not found');
 const a=await env.DB.prepare(`SELECT a.id,a.locked,a.published,s.date,s.start_time,s.end_time,t.name task_name,d.name department_name FROM assignments a JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id LEFT JOIN departments d ON d.id=t.department_id WHERE a.event_id=? AND a.volunteer_id=? ORDER BY s.date,s.start_time,t.name`).bind(eventId,vp.volunteer_id).all<any>();
 const c=await env.DB.prepare(`SELECT c.assignment_id,c.status,c.responded_at,c.response_note FROM confirmations c JOIN assignments a ON a.id=c.assignment_id WHERE c.event_id=? AND a.volunteer_id=? ORDER BY a.id`).bind(eventId,vp.volunteer_id).all<any>();
 const av=await env.DB.prepare(`SELECT s.id slot_id,s.date,s.start_time,s.end_time,t.name task_name,d.name department_name FROM availability av JOIN slots s ON s.id=av.slot_id JOIN tasks t ON t.id=s.task_id LEFT JOIN departments d ON d.id=t.department_id WHERE av.event_id=? AND av.volunteer_id=? ORDER BY s.date,s.start_time,t.name`).bind(eventId,vp.volunteer_id).all<any>();
 return json({ok:true,volunteer:v,schedule:a.results,confirmations:c.results,availability:av.results,availability_mode:av.results.length?'Selected Times':'Entire Event'});
}
async function areaPermission(env:Env,eventId:string,email:string){return env.DB.prepare(`SELECT department_id,scope_ref_id area_id,COALESCE(role,scope) role FROM app_permissions WHERE event_id=? AND lower(email)=lower(?) AND COALESCE(role,scope) IN ('Keyman','Captain') AND scope_ref_id IS NOT NULL ORDER BY created_at LIMIT 1`).bind(eventId,email).first<any>()}
async function myArea(req:Request,env:Env,eventId:string){
 const email=accessEmail(req),ap=await areaPermission(env,eventId,email);if(!ap?.area_id)return json({ok:false,error:'Keyman/Captain area access is not assigned to this account.'},403);
 const area=await env.DB.prepare(`SELECT a.id,a.label,a.department_id,d.name department_name FROM assistant_areas a JOIN departments d ON d.id=a.department_id WHERE a.id=? AND a.event_id=? AND a.department_id=?`).bind(ap.area_id,eventId,ap.department_id).first<any>();if(!area)return nf('Assigned area not found');
 const [v,t,sch]=await Promise.all([
  env.DB.prepare(`SELECT id,first_name,last_name,gender,email,phone,family FROM volunteers WHERE event_id=? AND department_id=? AND assistant_area_id=? AND active=1 ORDER BY last_name,first_name`).bind(eventId,ap.department_id,ap.area_id).all<any>(),
  env.DB.prepare(`SELECT id,name,description,active,auto_schedule FROM tasks WHERE event_id=? AND department_id=? AND assistant_area_id=? AND active=1 ORDER BY name`).bind(eventId,ap.department_id,ap.area_id).all<any>(),
  env.DB.prepare(`SELECT a.id,v.first_name,v.last_name,s.date,s.start_time,s.end_time,t.name task_name FROM assignments a JOIN volunteers v ON v.id=a.volunteer_id JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id WHERE a.event_id=? AND t.department_id=? AND t.assistant_area_id=? ORDER BY s.date,s.start_time,t.name,v.last_name,v.first_name`).bind(eventId,ap.department_id,ap.area_id).all<any>()
 ]);
 return json({ok:true,role:ap.role,area,volunteers:v.results,tasks:t.results,schedule:sch.results});
}
async function permissionData(env:Env,eventId:string){
 const [r,a]=await Promise.all([
  env.DB.prepare(`SELECT id,event_id,email,department_id,scope,scope_ref_id,COALESCE(role,scope) role,created_at,updated_at FROM app_permissions WHERE event_id=? ORDER BY lower(email),scope,role`).bind(eventId).all<any>(),
  env.DB.prepare(`SELECT id,email,'Full Admin' role,created_at,updated_at FROM app_admins WHERE active=1 ORDER BY lower(email)`).all<any>()
 ]);return json({ok:true,permissions:r.results,full_admins:a.results})
}
async function addPermission(req:Request,env:Env,eventId:string){
 const b=await body(req);if(!b)return bad('Invalid JSON');const email=clean(b.email).toLowerCase(),role=clean(b.role);if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return bad('A valid email address is required.');
 const allowed=['Full Admin','Event Admin','Committee','Department Overseer','Department Assistant','Keyman','Captain','Volunteer'];if(!allowed.includes(role))return bad('Select a valid permission role.');const now=new Date().toISOString();
 if(role==='Full Admin'){await env.DB.prepare(`INSERT INTO app_admins(id,email,active,created_at,updated_at) VALUES(?,?,1,?,?) ON CONFLICT(email) DO UPDATE SET active=1,updated_at=excluded.updated_at`).bind(crypto.randomUUID(),email,now,now).run();return json({ok:true},201)}
 let scope='Event Admin',departmentId:string|null=null,ref='';
 if(role==='Committee'){scope='Committee';ref=clean(b.scope_ref_id);if(!ref)return bad('Select a committee position.');const x=await env.DB.prepare(`SELECT id FROM org_nodes WHERE id=? AND event_id=? AND node_type='Committee Member'`).bind(ref,eventId).first();if(!x)return bad('Committee position not found.')}
 else if(['Department Overseer','Department Assistant'].includes(role)){scope='Department';departmentId=clean(b.department_id);ref=departmentId;if(!departmentId)return bad('Select a department.');const x=await env.DB.prepare(`SELECT id FROM departments WHERE id=? AND event_id=?`).bind(departmentId,eventId).first();if(!x)return bad('Department not found.')}
 else if(['Keyman','Captain'].includes(role)){scope='Area';departmentId=clean(b.department_id);ref=clean(b.scope_ref_id);if(!departmentId||!ref)return bad('Select an Assistant area.');const x=await env.DB.prepare(`SELECT id FROM assistant_areas WHERE id=? AND event_id=? AND department_id=? AND active=1`).bind(ref,eventId,departmentId).first();if(!x)return bad('Assistant area not found.')}
 else if(role==='Volunteer'){scope='Schedule View';ref=clean(b.scope_ref_id);if(!ref)return bad('Select a volunteer.');const x=await env.DB.prepare(`SELECT id FROM volunteers WHERE id=? AND event_id=?`).bind(ref,eventId).first();if(!x)return bad('Volunteer not found.')}
 const id=crypto.randomUUID();await env.DB.prepare(`INSERT INTO app_permissions(id,event_id,email,department_id,scope,scope_ref_id,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id,email,scope,scope_ref_id) DO UPDATE SET role=excluded.role,department_id=excluded.department_id,updated_at=excluded.updated_at`).bind(id,eventId,email,departmentId,scope,ref,role,now,now).run();return json({ok:true},201)
}
async function deletePermission(req:Request,env:Env,eventId:string,id:string){
 const u=new URL(req.url);if(u.searchParams.get('full_admin')==='1'){const email=clean(u.searchParams.get('email'));const current=accessEmail(req);if(email.toLowerCase()===current.toLowerCase())return bad('You cannot remove your own Full Admin access while signed in.');const c=await env.DB.prepare(`SELECT COUNT(*) c FROM app_admins WHERE active=1`).first<{c:number}>();if(Number(c?.c||0)<=1)return bad('At least one Full Admin is required.');await env.DB.prepare(`UPDATE app_admins SET active=0,updated_at=? WHERE lower(email)=lower(?)`).bind(new Date().toISOString(),email).run();return json({ok:true})}
 const r=await env.DB.prepare(`DELETE FROM app_permissions WHERE id=? AND event_id=?`).bind(id,eventId).run();return r.meta.changes?json({ok:true}):nf('Permission not found')
}

const APP_NAMES:Record<AppCode,string>={ca:'Event Scheduling',rc:'Event Scheduling',sc:'Event Scheduling'};
const ROLES:Role[]=['Overseer','Assistant','Keyman','Captain'];

const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8'}});
const bad=(m:string)=>json({ok:false,error:m},400);
const nf=(m='Not found')=>json({ok:false,error:m},404);
const clean=(v:unknown)=>typeof v==='string'?v.trim():'';
const isApp=(v:string|null):v is AppCode=>v==='ca'||v==='rc'||v==='sc';
const validDate=(v:string)=>/^\d{4}-\d{2}-\d{2}$/.test(v);
async function body(req:Request){try{const x=await req.json();return x&&typeof x==='object'&&!Array.isArray(x)?x as Record<string,unknown>:null}catch{return null}}

async function getEvent(env:Env,id:string){
  return env.DB.prepare(`SELECT id,app,name,start_date,end_date,status,structure_mode,entry_enabled,entry_token_hash,schedule_locked_at,created_at,updated_at FROM events WHERE id=?`).bind(id).first<EventRow>();
}
async function listEvents(req:Request,env:Env){
  const u=new URL(req.url), app=u.searchParams.get('app'), status=u.searchParams.get('status')||'Active',email=accessEmail(req);
  if(!isApp(app))return bad('app must be ca, rc, or sc');
  if(!['Active','Archived','All'].includes(status))return bad('Invalid status');
  const full=await isFullAdmin(env,email),statusSql=status==='All'?'':' AND e.status=?';
  const sql=full?`SELECT e.* FROM events e WHERE e.app=?${statusSql} ORDER BY e.start_date DESC,e.name COLLATE NOCASE`:`SELECT DISTINCT e.* FROM events e JOIN app_permissions p ON p.event_id=e.id AND lower(p.email)=lower(?) WHERE e.app=?${statusSql} ORDER BY e.start_date DESC,e.name COLLATE NOCASE`;
  const args:any[]=full?[app]:[email,app];if(status!=='All')args.push(status);
  const r=await env.DB.prepare(sql).bind(...args).all<EventRow>();return json({ok:true,events:r.results,full_admin:full});
}
async function ensureFullCommitteePositions(env:Env,eventId:string){
  const titles=['Committee Coordinator','Program Overseer','Rooming Overseer'];
  const existing=await env.DB.prepare(`SELECT id,label FROM org_nodes WHERE event_id=? AND node_type='Committee Member' AND department_id IS NULL ORDER BY sort_order,id`).bind(eventId).all<any>();
  const byTitle=new Map(existing.results.map(x=>[x.label,x]));
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];
  for(let i=0;i<titles.length;i++){
    const title=titles[i];
    if(!byTitle.has(title)) stmts.push(env.DB.prepare(`INSERT INTO org_nodes(id,event_id,department_id,parent_id,node_type,label,person_id,sort_order,created_at,updated_at) VALUES(?,?,NULL,NULL,'Committee Member',?,NULL,?,?,?)`).bind(crypto.randomUUID(),eventId,title,i,now,now));
  }
  if(stmts.length)await env.DB.batch(stmts);
}

async function createEvent(req:Request,env:Env){
  const b=await body(req); if(!b)return bad('Invalid JSON');
  const app=clean(b.app),name=clean(b.name),sd=clean(b.start_date),ed=clean(b.end_date),structure=clean(b.structure_mode)||'Simple';
  if(!isApp(app)||!name||!validDate(sd)||!validDate(ed)||ed<sd||!['Simple','Full'].includes(structure))return bad('Check event name, dates, and structure');
  const id=crypto.randomUUID(),now=new Date().toISOString();
  await env.DB.prepare(`INSERT INTO events(id,app,name,start_date,end_date,status,entry_enabled,structure_mode,created_at,updated_at) VALUES(?,?,?,?,?,'Active',0,?,?,?)`).bind(id,app,name,sd,ed,structure,now,now).run();
  if(structure==='Full')await ensureFullCommitteePositions(env,id);
  return json({ok:true,event:await getEvent(env,id)},201);
}
async function patchEvent(req:Request,env:Env,id:string){
  const e=await getEvent(env,id); if(!e)return nf('Event not found');
  const b=await body(req); if(!b)return bad('Invalid JSON');
  const name=b.name===undefined?e.name:clean(b.name),sd=b.start_date===undefined?e.start_date:clean(b.start_date),ed=b.end_date===undefined?e.end_date:clean(b.end_date),status=b.status===undefined?e.status:clean(b.status),structure=b.structure_mode===undefined?e.structure_mode:clean(b.structure_mode);
  if(!name||!validDate(sd)||!validDate(ed)||ed<sd||!['Active','Archived'].includes(status)||!['Simple','Full'].includes(structure))return bad('Invalid event values');
  if(e.structure_mode==='Full'&&structure==='Simple')return bad('A Full Organization event cannot be changed back to Simple while organization data may exist.');
  await env.DB.prepare(`UPDATE events SET name=?,start_date=?,end_date=?,status=?,structure_mode=?,updated_at=? WHERE id=?`).bind(name,sd,ed,status,structure,new Date().toISOString(),id).run();
  if(structure==='Full')await ensureFullCommitteePositions(env,id);
  return json({ok:true,event:await getEvent(env,id)});
}

async function eventForApp(env:Env,eventId:string,app:string|null){
  const e=await getEvent(env,eventId); return e && (!app || e.app===app) ? e : null;
}
async function rolesFor(env:Env,ids:string[]){
  const map:Record<string,string[]>={}; if(!ids.length)return map;
  const marks=ids.map(()=>'?').join(',');
  const r=await env.DB.prepare(`SELECT volunteer_id,role FROM volunteer_roles WHERE volunteer_id IN (${marks}) ORDER BY role`).bind(...ids).all<{volunteer_id:string,role:string}>();
  for(const x of r.results)(map[x.volunteer_id]??=[]).push(x.role); return map;
}
async function listVolunteers(req:Request,env:Env,eventId:string){
  const e=await getEvent(env,eventId); if(!e)return nf('Event not found');
  const u=new URL(req.url),q=clean(u.searchParams.get('q')),departmentId=clean(u.searchParams.get('department_id'));
  const like=`%${q}%`;
  const where=departmentId?'event_id=? AND department_id=?':'event_id=?', base=departmentId?[eventId,departmentId]:[eventId];
  const r=q
    ? await env.DB.prepare(`SELECT * FROM volunteers WHERE ${where} AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR phone LIKE ? OR family LIKE ?) ORDER BY last_name COLLATE NOCASE,first_name COLLATE NOCASE`).bind(...base,like,like,like,like,like).all<VolunteerRow>()
    : await env.DB.prepare(`SELECT * FROM volunteers WHERE ${where} ORDER BY last_name COLLATE NOCASE,first_name COLLATE NOCASE`).bind(...base).all<VolunteerRow>();
  const rm=await rolesFor(env,r.results.map(x=>x.id));
  return json({ok:true,volunteers:r.results.map(x=>({...x,roles:rm[x.id]||[]}))});
}
function parseVolunteer(b:Record<string,unknown>){
  const first=clean(b.first_name),last=clean(b.last_name),gender=clean(b.gender),email=clean(b.email),phone=clean(b.phone),family=last;
  const active=b.active===false||b.active===0?0:1;
  const roles=Array.isArray(b.roles)?[...new Set(b.roles.map(clean).filter(x=>ROLES.includes(x as Role)))]:[];
  if(!first||!last)return {error:'First and last name are required'} as const;
  if(gender!=='Male'&&gender!=='Female')return {error:'Gender must be Male or Female'} as const;
  return {value:{first,last,gender,email,phone,family,active,roles}} as const;
}
async function createVolunteer(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req); if(!b)return bad('Invalid JSON'); const p=parseVolunteer(b); if('error'in p)return bad(p.error);
  const v=p.value,id=crypto.randomUUID(),now=new Date().toISOString();
  const dep=clean(b.department_id)||(await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(eventId).first<{id:string}>())?.id||'';
  if(!dep)return bad('Create a department first');
  const stmts=[env.DB.prepare(`INSERT INTO volunteers(id,event_id,first_name,last_name,gender,email,phone,family,active,created_at,updated_at,department_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,eventId,v.first,v.last,v.gender,v.email||null,v.phone||null,v.family||null,v.active,now,now,dep),
    ...v.roles.map(r=>env.DB.prepare(`INSERT INTO volunteer_roles(volunteer_id,role) VALUES(?,?)`).bind(id,r))];
  await env.DB.batch(stmts); return json({ok:true,id},201);
}
async function patchVolunteer(req:Request,env:Env,eventId:string,id:string){
  const existing=await env.DB.prepare(`SELECT * FROM volunteers WHERE id=? AND event_id=?`).bind(id,eventId).first<VolunteerRow>(); if(!existing)return nf('Volunteer not found');
  const b=await body(req); if(!b)return bad('Invalid JSON');
  const oldRoles=(await rolesFor(env,[id]))[id]||[];
  const merged={first_name:b.first_name??existing.first_name,last_name:b.last_name??existing.last_name,gender:b.gender??existing.gender,email:b.email??existing.email??'',phone:b.phone??existing.phone??'',family:b.family??existing.family??'',active:b.active??existing.active,roles:b.roles??oldRoles};
  const p=parseVolunteer(merged); if('error'in p)return bad(p.error); const v=p.value;
  const stmts=[env.DB.prepare(`UPDATE volunteers SET first_name=?,last_name=?,gender=?,email=?,phone=?,family=?,active=?,updated_at=? WHERE id=? AND event_id=?`).bind(v.first,v.last,v.gender,v.email||null,v.phone||null,v.family||null,v.active,new Date().toISOString(),id,eventId),
    env.DB.prepare(`DELETE FROM volunteer_roles WHERE volunteer_id=?`).bind(id),
    ...v.roles.map(r=>env.DB.prepare(`INSERT INTO volunteer_roles(volunteer_id,role) VALUES(?,?)`).bind(id,r))];
  await env.DB.batch(stmts); return json({ok:true});
}
async function deleteVolunteers(req:Request,env:Env,eventId:string){
  const b=await body(req); if(!b||!Array.isArray(b.ids)||!b.ids.length)return bad('ids[] is required');
  const ids=[...new Set(b.ids.map(clean).filter(Boolean))].slice(0,500); if(!ids.length)return bad('No valid IDs');
  const marks=ids.map(()=>'?').join(',');
  const owned=await env.DB.prepare(`SELECT id FROM volunteers WHERE event_id=? AND id IN (${marks})`).bind(eventId,...ids).all<{id:string}>();
  if(owned.results.length!==ids.length)return bad('One or more volunteers do not belong to this event');
  await env.DB.batch(ids.map(id=>env.DB.prepare(`DELETE FROM volunteers WHERE id=? AND event_id=?`).bind(id,eventId)));
  return json({ok:true,deleted:ids.length});
}
async function importVolunteers(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req); if(!b||!Array.isArray(b.volunteers))return bad('volunteers[] is required');
  if(b.volunteers.length>500)return bad('Maximum 500 volunteers per batch');
  const parsed:any[]=[]; const errors:any[]=[];
  b.volunteers.forEach((x,i)=>{if(!x||typeof x!=='object'){errors.push({row:i+1,error:'Invalid row'});return}const p=parseVolunteer(x as any);if('error'in p)errors.push({row:i+1,error:p.error});else parsed.push({row:i+1,...p.value})});
  if(errors.length)return json({ok:false,error:'Import validation failed',errors},400);
  const departmentId=clean(b.department_id)||(await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(eventId).first<{id:string}>())?.id||'';if(!departmentId)return bad('Create a department first');
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];
  for(const v of parsed){const id=crypto.randomUUID();stmts.push(env.DB.prepare(`INSERT INTO volunteers(id,event_id,first_name,last_name,gender,email,phone,family,active,created_at,updated_at,department_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,eventId,v.first,v.last,v.gender,v.email||null,v.phone||null,v.family||null,v.active,now,now,departmentId)); for(const r of v.roles)stmts.push(env.DB.prepare(`INSERT INTO volunteer_roles(volunteer_id,role) VALUES(?,?)`).bind(id,r))}
  if(stmts.length)await env.DB.batch(stmts); return json({ok:true,imported:parsed.length});
}


const ELIGIBILITY = ['Anyone','Male Only','Female Only','Family Only','Overseer','Assistant','Keyman','Captain'] as const;
function parseTask(b:Record<string,unknown>){
  const name=clean(b.name),description=clean(b.description);
  const active=b.active===false||b.active===0?0:1;
  const autoSchedule=b.auto_schedule===false||b.auto_schedule===0?0:1;
  const eligibility=Array.isArray(b.eligibility)?[...new Set(b.eligibility.map(clean).filter(x=>(ELIGIBILITY as readonly string[]).includes(x)))]:[];
  if(!name)return {error:'Task name is required'} as const;
  if(!eligibility.length)return {error:'Select at least one eligibility option'} as const;
  if(eligibility.includes('Male Only')&&eligibility.includes('Female Only'))return {error:'A task cannot be both Male Only and Female Only'} as const;
  if(eligibility.includes('Anyone')&&eligibility.length>1)return {error:'Anyone must be used by itself'} as const;
  return {value:{name,description,active,autoSchedule,eligibility}} as const;
}
async function eligibilityFor(env:Env,ids:string[]){
  const map:Record<string,string[]>={}; if(!ids.length)return map;
  const marks=ids.map(()=>'?').join(',');
  const r=await env.DB.prepare(`SELECT task_id,value FROM task_eligibility WHERE task_id IN (${marks}) ORDER BY value`).bind(...ids).all<{task_id:string,value:string}>();
  for(const x of r.results)(map[x.task_id]??=[]).push(x.value); return map;
}
async function listTasks(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const departmentId=clean(new URL(req.url).searchParams.get('department_id'));
  const r=departmentId?await env.DB.prepare(`SELECT id,event_id,name,category,description,active,auto_schedule,created_at,updated_at,department_id,assistant_area_id,library_task_id FROM tasks WHERE event_id=? AND department_id=? ORDER BY category COLLATE NOCASE,name COLLATE NOCASE`).bind(eventId,departmentId).all<any>():await env.DB.prepare(`SELECT id,event_id,name,category,description,active,auto_schedule,created_at,updated_at,department_id,assistant_area_id,library_task_id FROM tasks WHERE event_id=? ORDER BY category COLLATE NOCASE,name COLLATE NOCASE`).bind(eventId).all<any>();
  const em=await eligibilityFor(env,r.results.map((x:any)=>x.id));
  return json({ok:true,tasks:r.results.map((x:any)=>({...x,eligibility:em[x.id]||[]}))});
}
async function createTask(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req); if(!b)return bad('Invalid JSON'); const p=parseTask(b); if('error'in p)return bad(p.error);
  const t=p.value,id=crypto.randomUUID(),now=new Date().toISOString();
  const dep=clean(b.department_id)||(await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(eventId).first<{id:string}>())?.id||'';
  if(!dep)return bad('Create a department first');
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO tasks(id,event_id,name,category,description,active,auto_schedule,created_at,updated_at,department_id) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(id,eventId,t.name,'',t.description||null,t.active,t.autoSchedule,now,now,dep),
    ...t.eligibility.map(x=>env.DB.prepare(`INSERT INTO task_eligibility(task_id,value) VALUES(?,?)`).bind(id,x))
  ]);
  return json({ok:true,id},201);
}
async function patchTask(req:Request,env:Env,eventId:string,id:string){
  const old=await env.DB.prepare(`SELECT * FROM tasks WHERE id=? AND event_id=?`).bind(id,eventId).first<any>(); if(!old)return nf('Task not found');
  const b=await body(req); if(!b)return bad('Invalid JSON'); const oldE=(await eligibilityFor(env,[id]))[id]||[];
  const p=parseTask({name:b.name??old.name,description:b.description??old.description??'',active:b.active??old.active,auto_schedule:b.auto_schedule??old.auto_schedule,eligibility:b.eligibility??oldE});
  if('error'in p)return bad(p.error); const t=p.value;
  await env.DB.batch([
    env.DB.prepare(`UPDATE tasks SET name=?,category=?,description=?,active=?,auto_schedule=?,updated_at=? WHERE id=? AND event_id=?`).bind(t.name,'',t.description||null,t.active,t.autoSchedule,new Date().toISOString(),id,eventId),
    env.DB.prepare(`DELETE FROM task_eligibility WHERE task_id=?`).bind(id),
    ...t.eligibility.map(x=>env.DB.prepare(`INSERT INTO task_eligibility(task_id,value) VALUES(?,?)`).bind(id,x))
  ]);
  return json({ok:true});
}
async function deleteTask(env:Env,eventId:string,id:string){
  const t=await env.DB.prepare(`SELECT id FROM tasks WHERE id=? AND event_id=?`).bind(id,eventId).first();
  if(!t)return nf('Task not found');
  const used=await env.DB.prepare(`SELECT COUNT(*) c FROM slots WHERE task_id=?`).bind(id).first<{c:number}>();
  if((used?.c||0)>0)return bad('This task has slots and cannot be deleted yet.');
  await env.DB.prepare(`DELETE FROM tasks WHERE id=? AND event_id=?`).bind(id,eventId).run();
  return json({ok:true});
}

// Shared rule for Stage 4 scheduler:
// gender restrictions are AND constraints; selected roles are OR constraints.
// Exact Anyone is handled separately by the v58 same-gender/same-last-name-family slot rule.
export function eligibilityAllowsVolunteer(gender:string, volunteerRoles:string[], values:string[]):boolean{
  if(values.length===1&&values[0]==='Anyone')return true;
  if(values.includes('Male Only')&&gender!=='Male')return false;
  if(values.includes('Female Only')&&gender!=='Female')return false;
  const requiredRoles=values.filter(v=>['Overseer','Assistant','Keyman','Captain'].includes(v));
  return !requiredRoles.length || requiredRoles.some(r=>volunteerRoles.includes(r));
}


function validTime(v:string){ return /^\d{2}:\d{2}$/.test(v); }
async function listSlots(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const r=await env.DB.prepare(`
    SELECT s.id,s.event_id,s.task_id,s.date,s.start_time,s.end_time,s.positions_needed,
           s.created_at,s.updated_at,t.name AS task_name
    FROM slots s
    JOIN tasks t ON t.id=s.task_id AND t.event_id=s.event_id
    WHERE s.event_id=? AND (?='' OR t.department_id=?)
    ORDER BY s.date,s.start_time,t.name COLLATE NOCASE,s.id
  `).bind(eventId,clean(new URL(req.url).searchParams.get('department_id')),clean(new URL(req.url).searchParams.get('department_id'))).all<any>();
  return json({ok:true,slots:r.results});
}
function parseSlot(x:Record<string,unknown>){
  const id=clean(x.id),taskId=clean(x.task_id),date=clean(x.date),start=clean(x.start_time),end=clean(x.end_time);
  const positions=Number(x.positions_needed);
  if(!taskId)return {error:'Task is required'} as const;
  if(!validDate(date))return {error:'Valid date is required'} as const;
  if(!validTime(start))return {error:'Valid start time is required'} as const;
  if(end && !validTime(end))return {error:'End time must be blank or valid'} as const;
  if(end && end<=start)return {error:'End time must be after start time'} as const;
  if(!Number.isInteger(positions)||positions<1||positions>100)return {error:'Positions needed must be between 1 and 100'} as const;
  return {value:{id,taskId,date,start,end,positions}} as const;
}
async function saveSlots(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req); if(!b||!Array.isArray(b.slots))return bad('slots[] is required');
  if(b.slots.length>1000)return bad('Too many slots in one save');
  const parsed:any[]=[];
  for(let i=0;i<b.slots.length;i++){
    const x=b.slots[i];
    if(!x||typeof x!=='object')return bad(`Row ${i+1}: invalid slot`);
    const p=parseSlot(x as Record<string,unknown>);
    if('error'in p)return bad(`Row ${i+1}: ${p.error}`);
    parsed.push(p.value);
  }
  const deleteIds=Array.isArray(b.delete_ids)?[...new Set(b.delete_ids.map(clean).filter(Boolean))]:[];
  const taskIds=[...new Set(parsed.map(x=>x.taskId))];
  if(taskIds.length){
    const marks=taskIds.map(()=>'?').join(',');
    const tasks=await env.DB.prepare(`SELECT id FROM tasks WHERE event_id=? AND id IN (${marks})`).bind(eventId,...taskIds).all<{id:string}>();
    if(tasks.results.length!==taskIds.length)return bad('One or more selected tasks do not belong to this event');
  }
  if(deleteIds.length){
    const marks=deleteIds.map(()=>'?').join(',');
    const owned=await env.DB.prepare(`SELECT id FROM slots WHERE event_id=? AND id IN (${marks})`).bind(eventId,...deleteIds).all<{id:string}>();
    if(owned.results.length!==deleteIds.length)return bad('One or more deleted slots do not belong to this event');
    const used=await env.DB.prepare(`SELECT DISTINCT slot_id FROM assignments WHERE event_id=? AND slot_id IN (${marks})`).bind(eventId,...deleteIds).all<{slot_id:string}>();
    if(used.results.length)return bad('This time slot already has assignments. Remove the assignments first.');
  }
  const now=new Date().toISOString(), stmts:D1PreparedStatement[]=[];
  for(const id of deleteIds)stmts.push(env.DB.prepare(`DELETE FROM slots WHERE id=? AND event_id=?`).bind(id,eventId));
  for(const s of parsed){
    if(s.id){
      const exists=await env.DB.prepare(`SELECT id FROM slots WHERE id=? AND event_id=?`).bind(s.id,eventId).first();
      if(!exists)return bad('A slot being edited no longer exists');
      stmts.push(env.DB.prepare(`UPDATE slots SET task_id=?,date=?,start_time=?,end_time=?,positions_needed=?,updated_at=? WHERE id=? AND event_id=?`)
        .bind(s.taskId,s.date,s.start,s.end||null,s.positions,now,s.id,eventId));
    }else{
      stmts.push(env.DB.prepare(`INSERT INTO slots(id,event_id,task_id,date,start_time,end_time,positions_needed,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`)
        .bind(crypto.randomUUID(),eventId,s.taskId,s.date,s.start,s.end||null,s.positions,now,now));
    }
  }
  if(stmts.length)await env.DB.batch(stmts);
  return json({ok:true,saved:parsed.length,deleted:deleteIds.length});
}
async function copySlots(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req);if(!b)return bad('Invalid JSON');
  const sourceTaskId=clean(b.source_task_id),targetTaskId=clean(b.target_task_id);
  if(!sourceTaskId||!targetTaskId)return bad('Select both the source task and destination task.');
  if(sourceTaskId===targetTaskId)return bad('Source and destination tasks must be different.');
  const tasks=await env.DB.prepare(`SELECT id,name FROM tasks WHERE event_id=? AND id IN (?,?)`).bind(eventId,sourceTaskId,targetTaskId).all<{id:string,name:string}>();
  if(tasks.results.length!==2)return bad('One or both tasks were not found in this event.');
  const source=await env.DB.prepare(`SELECT date,start_time,end_time,positions_needed FROM slots WHERE event_id=? AND task_id=? ORDER BY date,start_time`).bind(eventId,sourceTaskId).all<any>();
  if(!source.results.length)return bad('The source task has no configured time slots to copy.');
  const existing=await env.DB.prepare(`SELECT date,start_time,end_time FROM slots WHERE event_id=? AND task_id=?`).bind(eventId,targetTaskId).all<any>();
  const keys=new Set(existing.results.map((x:any)=>`${x.date}|${x.start_time}|${x.end_time||''}`));
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];let skipped=0;
  for(const s of source.results){
    const key=`${s.date}|${s.start_time}|${s.end_time||''}`;
    if(keys.has(key)){skipped++;continue;}
    keys.add(key);
    stmts.push(env.DB.prepare(`INSERT INTO slots(id,event_id,task_id,date,start_time,end_time,positions_needed,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`)
      .bind(crypto.randomUUID(),eventId,targetTaskId,s.date,s.start_time,s.end_time,s.positions_needed,now,now));
  }
  if(stmts.length)await env.DB.batch(stmts);
  const sm=new Map(tasks.results.map(t=>[t.id,t.name]));
  return json({ok:true,copied:stmts.length,skipped,source_task:sm.get(sourceTaskId),target_task:sm.get(targetTaskId)});
}

async function getAvailability(env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const r=await env.DB.prepare(`SELECT volunteer_id,slot_id FROM availability WHERE event_id=? ORDER BY volunteer_id,slot_id`).bind(eventId).all<{volunteer_id:string,slot_id:string}>();
  const byVolunteer:Record<string,string[]>={};
  for(const x of r.results)(byVolunteer[x.volunteer_id]??=[]).push(x.slot_id);
  return json({ok:true,availability:byVolunteer});
}
async function saveVolunteerAvailability(req:Request,env:Env,eventId:string,volunteerId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const v=await env.DB.prepare(`SELECT id FROM volunteers WHERE id=? AND event_id=?`).bind(volunteerId,eventId).first();
  if(!v)return nf('Volunteer not found');
  const b=await body(req); if(!b||!Array.isArray(b.slot_ids))return bad('slot_ids[] is required');
  const ids=[...new Set(b.slot_ids.map(clean).filter(Boolean))];
  if(ids.length){
    const marks=ids.map(()=>'?').join(',');
    const owned=await env.DB.prepare(`SELECT id FROM slots WHERE event_id=? AND id IN (${marks})`).bind(eventId,...ids).all<{id:string}>();
    if(owned.results.length!==ids.length)return bad('One or more availability slots do not belong to this event');
  }
  const stmts:D1PreparedStatement[]=[env.DB.prepare(`DELETE FROM availability WHERE event_id=? AND volunteer_id=?`).bind(eventId,volunteerId)];
  const now=new Date().toISOString();
  for(const slotId of ids)stmts.push(env.DB.prepare(`INSERT INTO availability(event_id,volunteer_id,slot_id,created_at) VALUES(?,?,?,?)`).bind(eventId,volunteerId,slotId,now));
  await env.DB.batch(stmts);
  return json({ok:true,mode:ids.length?'selected':'all',slot_ids:ids});
}

type SchedVolunteer={id:string,first_name:string,last_name:string,gender:string,family:string|null,created_at:string,department_id:string|null,assistant_area_id:string|null,roles:string[]};
type SchedSlot={id:string,event_id:string,task_id:string,date:string,start_time:string,end_time:string|null,positions_needed:number,task_name:string,auto_schedule:number,department_id:string|null,assistant_area_id:string|null,eligibility:string[]};
type SchedAssignment={id:string,event_id:string,slot_id:string,volunteer_id:string,locked:number,published:number,created_at:string,date?:string,start_time?:string,end_time?:string|null,task_name?:string};

function slotOverlaps(a:{date:string,start_time:string,end_time?:string|null},b:{date:string,start_time:string,end_time?:string|null}){
  if(a.date!==b.date)return false;
  const s1=a.start_time,e1=a.end_time||'',s2=b.start_time,e2=b.end_time||'';
  if(!e1&&!e2)return s1===s2;
  if(!e1)return s1>=s2&&s1<e2;
  if(!e2)return s2>=s1&&s2<e1;
  return s1<e2&&e1>s2;
}
function allowsEligibility(v:SchedVolunteer,values:string[]){
  if(values.length===1&&values[0]==='Anyone')return true;
  if(values.includes('Male Only')&&v.gender!=='Male')return false;
  if(values.includes('Female Only')&&v.gender!=='Female')return false;
  const roles=values.filter(x=>['Overseer','Assistant','Keyman','Captain'].includes(x));
  return !roles.length||roles.some(r=>v.roles.includes(r));
}
function anyoneCompatible(v:SchedVolunteer,slot:SchedSlot,assigned:{volunteer_id:string,slot_id:string}[],vm:Map<string,SchedVolunteer>){
  const peers=assigned.filter(a=>a.slot_id===slot.id).map(a=>vm.get(a.volunteer_id)).filter(Boolean) as SchedVolunteer[];
  if(!peers.length)return true;
  if(slot.eligibility.includes('Family Only')){
    const fam=v.family?.trim().toLowerCase();
    return !!fam&&peers.every(p=>p.family?.trim().toLowerCase()===fam);
  }
  if(!(slot.eligibility.length===1&&slot.eligibility[0]==='Anyone'))return true;
  return peers.every(p=>p.gender===v.gender || (!!p.family&&!!v.family&&p.family.toLowerCase()===v.family.toLowerCase()));
}
async function schedulingData(env:Env,eventId:string,departmentId=''){
  const vr=await env.DB.prepare(`SELECT id,first_name,last_name,gender,family,created_at,department_id,assistant_area_id FROM volunteers WHERE event_id=? AND active=1`).bind(eventId).all<any>();
  const rr=await env.DB.prepare(`SELECT volunteer_id,role FROM volunteer_roles WHERE volunteer_id IN (SELECT id FROM volunteers WHERE event_id=? AND active=1)`).bind(eventId).all<any>();
  const roleMap:Record<string,string[]>={};for(const r of rr.results)(roleMap[r.volunteer_id]??=[]).push(r.role);
  const volunteers:SchedVolunteer[]=vr.results.filter((v:any)=>!departmentId||v.department_id===departmentId).map((v:any)=>({...v,roles:roleMap[v.id]||[]}));
  const sr=await env.DB.prepare(`SELECT s.id,s.event_id,s.task_id,s.date,s.start_time,s.end_time,s.positions_needed,t.name task_name,t.auto_schedule,t.department_id,t.assistant_area_id FROM slots s JOIN tasks t ON t.id=s.task_id WHERE s.event_id=? AND t.active=1 ORDER BY s.date,s.start_time,t.name`).bind(eventId).all<any>();
  const er=await env.DB.prepare(`SELECT task_id,value FROM task_eligibility WHERE task_id IN (SELECT id FROM tasks WHERE event_id=?)`).bind(eventId).all<any>();
  const em:Record<string,string[]>={};for(const e of er.results)(em[e.task_id]??=[]).push(e.value);
  const slots:SchedSlot[]=sr.results.filter((s:any)=>!departmentId||s.department_id===departmentId).map((s:any)=>({...s,positions_needed:Number(s.positions_needed||1),eligibility:em[s.task_id]||[]}));
  const ar=await env.DB.prepare(`SELECT id,event_id,slot_id,volunteer_id,locked,published,created_at FROM assignments WHERE event_id=?`).bind(eventId).all<any>();
  const av=await env.DB.prepare(`SELECT volunteer_id,slot_id FROM availability WHERE event_id=?`).bind(eventId).all<any>();
  const avail:Record<string,Set<string>>={};for(const x of av.results)(avail[x.volunteer_id]??=new Set()).add(x.slot_id);
  const xr=await env.DB.prepare(`SELECT volunteer_id,slot_id FROM schedule_exclusions WHERE event_id=?`).bind(eventId).all<any>();
  const excluded=new Set(xr.results.map((x:any)=>`${x.volunteer_id}|${x.slot_id}`));
  const slotIds=new Set(slots.map(x=>x.id));return {volunteers,slots,assignments:(ar.results as SchedAssignment[]).filter(a=>!departmentId||slotIds.has(a.slot_id)),avail,excluded};
}


async function scheduleLockState(env:Env,eventId:string){
  const e=await env.DB.prepare(`SELECT schedule_locked_at FROM events WHERE id=?`).bind(eventId).first<{schedule_locked_at:string|null}>();
  if(!e)return nf('Event not found');
  return json({ok:true,locked:!!e.schedule_locked_at,locked_at:e.schedule_locked_at||''});
}
async function setEntireScheduleLock(env:Env,eventId:string,locked:boolean){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const now=new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(`UPDATE assignments SET locked=?,updated_at=? WHERE event_id=?`).bind(locked?1:0,now,eventId),
    env.DB.prepare(`UPDATE events SET schedule_locked_at=?,updated_at=? WHERE id=?`).bind(locked?now:null,now,eventId)
  ]);
  return json({ok:true,locked,locked_at:locked?now:''});
}
async function setOneAssignmentLock(env:Env,eventId:string,assignmentId:string,locked:boolean){
  const a=await env.DB.prepare(`SELECT id FROM assignments WHERE id=? AND event_id=?`).bind(assignmentId,eventId).first();
  if(!a)return nf('Assignment not found');
  await env.DB.prepare(`UPDATE assignments SET locked=?,updated_at=? WHERE id=? AND event_id=?`).bind(locked?1:0,new Date().toISOString(),assignmentId,eventId).run();
  return json({ok:true,locked});
}
async function removeScheduleAssignments(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const b=await body(req);if(!b||!Array.isArray(b.ids)||!b.ids.length)return bad('Select at least one assignment.');
  const ids=[...new Set(b.ids.map(clean).filter(Boolean))];
  const marks=ids.map(()=>'?').join(',');
  const rows=await env.DB.prepare(`SELECT id,slot_id,volunteer_id FROM assignments WHERE event_id=? AND id IN (${marks})`).bind(eventId,...ids).all<any>();
  if(rows.results.length!==ids.length)return bad('One or more selected assignments were not found.');
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];
  for(const a of rows.results){
    stmts.push(env.DB.prepare(`INSERT OR REPLACE INTO schedule_exclusions(event_id,slot_id,volunteer_id,reason,created_at) VALUES(?,?,?,?,?)`).bind(eventId,a.slot_id,a.volunteer_id,'Removed from schedule',now));
    stmts.push(env.DB.prepare(`DELETE FROM assignments WHERE id=? AND event_id=?`).bind(a.id,eventId));
  }
  await env.DB.batch(stmts);
  return json({ok:true,removed:rows.results.length});
}
async function validateAssignmentCandidate(env:Env,eventId:string,slotId:string,volunteerId:string,ignoreAssignmentId=''){
  const d=await schedulingData(env,eventId),s=d.slots.find(x=>x.id===slotId),v=d.volunteers.find(x=>x.id===volunteerId);
  if(!s||!v)return {error:'Volunteer or time slot was not found.'};
  if(!allowsEligibility(v,s.eligibility))return {error:'This volunteer does not meet the task eligibility requirements.'};
  if(s.department_id&&v.department_id!==s.department_id)return {error:'This volunteer belongs to a different department.'};
  if(s.assistant_area_id&&v.assistant_area_id!==s.assistant_area_id)return {error:'This volunteer belongs to a different Assistant area.'};
  if(d.avail[v.id]&&!d.avail[v.id].has(s.id))return {error:'This volunteer is not available for this time slot.'};
  const sm=new Map(d.slots.map(x=>[x.id,x])),vm=new Map(d.volunteers.map(x=>[x.id,x]));
  const assigned=d.assignments.filter(a=>a.id!==ignoreAssignmentId).map(a=>{const x=sm.get(a.slot_id);return x?{id:a.id,slot_id:a.slot_id,volunteer_id:a.volunteer_id,date:x.date,start_time:x.start_time,end_time:x.end_time,task_name:x.task_name}:null}).filter(Boolean) as any[];
  if(!anyoneCompatible(v,s,assigned,vm))return {error:s.eligibility.includes('Family Only')?'Family Only requires everyone in this slot to have the same family.':'For an Anyone task, volunteers in the same slot must be the same gender or have the same family.'};
  if(assigned.some(a=>a.volunteer_id===v.id&&slotOverlaps(s,a)))return {error:'This volunteer already has an overlapping assignment.'};
  return {ok:true};
}
async function changeAssignmentVolunteer(req:Request,env:Env,eventId:string,assignmentId:string){
  const a=await env.DB.prepare(`SELECT id,slot_id FROM assignments WHERE id=? AND event_id=?`).bind(assignmentId,eventId).first<{id:string,slot_id:string}>();
  if(!a)return nf('Assignment not found');
  const b=await body(req);if(!b)return bad('Invalid JSON');
  const volunteerId=clean(b.volunteer_id);if(!volunteerId)return bad('Volunteer is required');
  const check=await validateAssignmentCandidate(env,eventId,a.slot_id,volunteerId,assignmentId);
  if('error' in check)return bad(check.error);
  await env.DB.prepare(`UPDATE assignments SET volunteer_id=?,updated_at=? WHERE id=? AND event_id=?`).bind(volunteerId,new Date().toISOString(),assignmentId,eventId).run();
  return json({ok:true});
}
async function fillOpenScheduleSlots(env:Env,eventId:string){
  const d=await schedulingData(env,eventId);
  if(!d.volunteers.length)return bad('Add at least one active volunteer.');
  const sm=new Map(d.slots.map(s=>[s.id,s])),vm=new Map(d.volunteers.map(v=>[v.id,v]));
  const assigned:any[]=[];
  for(const a of d.assignments){const s=sm.get(a.slot_id);if(s)assigned.push({id:a.id,slot_id:a.slot_id,volunteer_id:a.volunteer_id,date:s.date,start_time:s.start_time,end_time:s.end_time,task_name:s.task_name});}
  const total:Record<string,number>={},taskCount:Record<string,Record<string,number>>={};
  d.volunteers.forEach(v=>{total[v.id]=0;taskCount[v.id]={}});
  for(const a of assigned){const s=sm.get(a.slot_id);if(s&&total[a.volunteer_id]!==undefined){total[a.volunteer_id]++;taskCount[a.volunteer_id][s.task_id]=(taskCount[a.volunteer_id][s.task_id]||0)+1}}
  const rows:any[][]=[];let unfilled=0;
  for(const s of d.slots){
    if(!Number(s.auto_schedule))continue;
    const need=Math.max(0,s.positions_needed-assigned.filter(a=>a.slot_id===s.id).length);
    for(let p=0;p<need;p++){
      const candidates=d.volunteers.filter(v=>{
        if(!allowsEligibility(v,s.eligibility))return false;
        if(s.department_id&&v.department_id!==s.department_id)return false;
        if(s.assistant_area_id&&v.assistant_area_id!==s.assistant_area_id)return false;
        if(d.avail[v.id]&&!d.avail[v.id].has(s.id))return false;
        if(d.excluded.has(`${v.id}|${s.id}`))return false;
        if(!anyoneCompatible(v,s,assigned,vm))return false;
        if(assigned.some(a=>a.volunteer_id===v.id&&slotOverlaps(s,a)))return false;
        return true;
      }).sort((a,b)=>(total[a.id]-total[b.id])||((taskCount[a.id][s.task_id]||0)-(taskCount[b.id][s.task_id]||0))||(Math.random()-.5));
      if(!candidates.length){unfilled++;continue}
      const v=candidates[0],id=crypto.randomUUID(),now=new Date().toISOString();
      rows.push([id,eventId,s.id,v.id,1,0,0,0,now,now]);
      assigned.push({id,slot_id:s.id,volunteer_id:v.id,date:s.date,start_time:s.start_time,end_time:s.end_time,task_name:s.task_name});
      total[v.id]++;taskCount[v.id][s.task_id]=(taskCount[v.id][s.task_id]||0)+1;
    }
  }
  if(rows.length)await env.DB.batch(rows.map(r=>env.DB.prepare(`INSERT INTO assignments(id,event_id,slot_id,volunteer_id,locked,published,email_sent,sms_sent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(...r)));
  return json({ok:true,created:rows.length,unfilled});
}

async function rebalanceWithNewVolunteers(env:Env,eventId:string){
  const event=await getEvent(env,eventId);if(!event)return nf('Event not found');
  if(!event.schedule_locked_at)return bad('Lock the entire schedule before rebalancing new volunteers.');
  const d=await schedulingData(env,eventId);
  const newVolunteers=d.volunteers.filter(v=>v.created_at>event.schedule_locked_at!);
  if(!newVolunteers.length)return json({ok:true,moved:0,new_volunteers:0,message:'No active volunteers have been added since the schedule was locked.'});
  const sm=new Map(d.slots.map(s=>[s.id,s])),vm=new Map(d.volunteers.map(v=>[v.id,v]));
  const assigned:any[]=[];
  for(const a of d.assignments){const s=sm.get(a.slot_id);if(s)assigned.push({id:a.id,slot_id:a.slot_id,volunteer_id:a.volunteer_id,date:s.date,start_time:s.start_time,end_time:s.end_time,task_name:s.task_name,locked:a.locked});}
  const counts:Record<string,number>={};d.volunteers.forEach(v=>counts[v.id]=0);assigned.forEach(a=>{if(counts[a.volunteer_id]!==undefined)counts[a.volunteer_id]++});
  const changes:{id:string,volunteer_id:string}[]=[];
  // Give the least-used new volunteers opportunities by transferring only when the
  // donor has at least two more assignments. That guarantees the count balance improves.
  let progress=true;
  while(progress){
    progress=false;
    const targets=[...newVolunteers].sort((a,b)=>counts[a.id]-counts[b.id]||a.last_name.localeCompare(b.last_name)||a.first_name.localeCompare(b.first_name));
    for(const nv of targets){
      const donorAssignments=assigned
        .filter(a=>a.volunteer_id!==nv.id && (counts[a.volunteer_id]||0)>counts[nv.id]+1)
        .sort((a,b)=>(counts[b.volunteer_id]-counts[a.volunteer_id])||String(a.date).localeCompare(String(b.date))||String(a.start_time).localeCompare(String(b.start_time)));
      for(const a of donorAssignments){
        const s=sm.get(a.slot_id);if(!s)continue;
        if(!allowsEligibility(nv,s.eligibility))continue;
        if(d.avail[nv.id]&&!d.avail[nv.id].has(s.id))continue;
        if(d.excluded.has(`${nv.id}|${s.id}`))continue;
        const others=assigned.filter(x=>x.id!==a.id);
        if(!anyoneCompatible(nv,s,others,vm))continue;
        if(others.some(x=>x.volunteer_id===nv.id&&slotOverlaps(s,x)))continue;
        const old=a.volunteer_id;
        a.volunteer_id=nv.id;
        counts[old]--;counts[nv.id]++;
        changes.push({id:a.id,volunteer_id:nv.id});
        progress=true;
        break;
      }
    }
  }
  if(changes.length){
    const now=new Date().toISOString();
    await env.DB.batch(changes.map(c=>env.DB.prepare(`UPDATE assignments SET volunteer_id=?,updated_at=? WHERE id=? AND event_id=?`).bind(c.volunteer_id,now,c.id,eventId)));
  }
  return json({ok:true,moved:changes.length,new_volunteers:newVolunteers.length,message:changes.length?`${changes.length} assignment(s) moved to volunteers added after the schedule was locked.`:'No eligible transfers would improve workload fairness.'});
}
async function schedulePreflight(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const dep=clean(new URL(req.url).searchParams.get('department_id'));
  const [v,t,s]=await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) n FROM volunteers WHERE event_id=? AND active=1 AND (?='' OR department_id=?)`).bind(eventId,dep,dep).first<{n:number}>(),
    env.DB.prepare(`SELECT COUNT(*) n FROM tasks WHERE event_id=? AND active=1 AND auto_schedule=1 AND (?='' OR department_id=?)`).bind(eventId,dep,dep).first<{n:number}>(),
    env.DB.prepare(`SELECT COUNT(*) n,COALESCE(SUM(positions_needed),0) positions FROM slots s JOIN tasks t ON t.id=s.task_id WHERE s.event_id=? AND t.active=1 AND t.auto_schedule=1 AND (?='' OR t.department_id=?)`).bind(eventId,dep,dep).first<{n:number,positions:number}>()
  ]);
  return json({ok:true,volunteers:Number(v?.n||0),tasks:Number(t?.n||0),slots:Number(s?.n||0),positions:Number(s?.positions||0)});
}
async function listSchedule(req:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  const r=await env.DB.prepare(`
   SELECT a.id,a.slot_id,a.volunteer_id,a.locked,a.published,a.created_at,
          v.first_name,v.last_name,v.gender,s.date,s.start_time,s.end_time,t.name task_name
   FROM assignments a JOIN volunteers v ON v.id=a.volunteer_id
   JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id
   WHERE a.event_id=? AND (?='' OR t.department_id=?) ORDER BY s.date,s.start_time,t.name,v.last_name,v.first_name
  `).bind(eventId,clean(new URL(req.url).searchParams.get('department_id')),clean(new URL(req.url).searchParams.get('department_id'))).all<any>();
  return json({ok:true,schedule:r.results});
}
async function generateSchedule(req:Request,env:Env,eventId:string){
  const event=await getEvent(env,eventId);if(!event)return nf('Event not found');
  const b=await body(req)||{},departmentId=clean(b.department_id);
  const d=await schedulingData(env,eventId,departmentId);
  if(!d.volunteers.length)return bad('Add at least one active volunteer before generating the schedule.');
  if(!d.slots.length)return bad('Add at least one active task and slot before generating the schedule.');

  // Build the complete replacement in memory first. The database is not changed
  // until every candidate decision has finished successfully.
  const locked=d.assignments.filter(a=>Number(a.locked)===1);
  const assigned:{id:string,slot_id:string,volunteer_id:string,date:string,start_time:string,end_time:string|null,task_name:string}[]=[];
  const sm=new Map(d.slots.map(s=>[s.id,s])),vm=new Map(d.volunteers.map(v=>[v.id,v]));
  for(const a of locked){const s=sm.get(a.slot_id);if(s)assigned.push({id:a.id,slot_id:a.slot_id,volunteer_id:a.volunteer_id,date:s.date,start_time:s.start_time,end_time:s.end_time,task_name:s.task_name});}

  const total:Record<string,number>={},weighted:Record<string,number>={},taskCount:Record<string,Record<string,number>>={},
        lateCount:Record<string,number>={},closingDays:Record<string,Set<string>>={},dayBands:Record<string,Record<string,string[]>>={};
  d.volunteers.forEach(v=>{total[v.id]=0;weighted[v.id]=0;taskCount[v.id]={};lateCount[v.id]=0;closingDays[v.id]=new Set();dayBands[v.id]={};});

  const byDay:Record<string,SchedSlot[]>={};for(const s of d.slots)(byDay[s.date]??=[]).push(s);
  const dayStarts:Record<string,string[]>={},closingStart:Record<string,string>={};
  for(const [day,ss] of Object.entries(byDay)){
    const starts=[...new Set(ss.map(s=>s.start_time))].sort();dayStarts[day]=starts;closingStart[day]=starts[starts.length-1]||'';
  }
  function band(s:SchedSlot){const a=dayStarts[s.date]||[];if(a.length<=1)return 'only';const i=a.indexOf(s.start_time);return i>=Math.ceil(a.length*2/3)?'late':i<Math.ceil(a.length/3)?'early':'mid';}
  function isClosing(s:SchedSlot){return !!closingStart[s.date]&&s.start_time===closingStart[s.date];}
  function record(vid:string,s:SchedSlot){
    total[vid]++;weighted[vid]+=isClosing(s)?2:1;taskCount[vid][s.task_id]=(taskCount[vid][s.task_id]||0)+1;
    const b=band(s);(dayBands[vid][s.date]??=[]).push(b);if(b==='late')lateCount[vid]++;if(isClosing(s))closingDays[vid].add(s.date);
  }
  for(const a of assigned){const s=sm.get(a.slot_id);if(s&&total[a.volunteer_id]!==undefined)record(a.volunteer_id,s);}

  const rows:any[][]=[];let unfilled=0;
  for(const s of d.slots){
    if(!Number(s.auto_schedule))continue;
    const already=assigned.filter(a=>a.slot_id===s.id).length,need=Math.max(0,s.positions_needed-already);
    for(let p=0;p<need;p++){
      const candidates=d.volunteers.filter(v=>{
        if(!allowsEligibility(v,s.eligibility))return false;
        if(s.department_id&&v.department_id!==s.department_id)return false;
        if(s.assistant_area_id&&v.assistant_area_id!==s.assistant_area_id)return false;
        if(d.avail[v.id]&&!d.avail[v.id].has(s.id))return false;
        if(d.excluded.has(`${v.id}|${s.id}`))return false;
        if(!anyoneCompatible(v,s,assigned,vm))return false;
        if(assigned.some(a=>a.volunteer_id===v.id&&slotOverlaps(s,a)))return false;
        return true;
      });
      if(!candidates.length){unfilled++;continue;}
      const sb=band(s),closing=isClosing(s);
      candidates.sort((a,b)=>{
        const score=(v:SchedVolunteer)=>{
          // Weighted workload is the primary fairness measure. A closing/final
          // shift counts approximately twice a normal assignment.
          let n=weighted[v.id]*100;
          // Repeating the exact same task is discouraged.
          n+=(taskCount[v.id][s.task_id]||0)*34;
          // Rotate late shifts across the event.
          if(sb==='late')n+=lateCount[v.id]*44;
          // Avoid repeatedly assigning the same part of the day on the same day.
          if((dayBands[v.id][s.date]||[]).includes(sb))n+=22;
          // Strongly avoid giving one person the closing/final shift on multiple days.
          if(closing&&closingDays[v.id].size)n+=closingDays[v.id].size*180;
          return n;
        };
        return score(a)-score(b)||(total[a.id]-total[b.id])||(Math.random()-.5);
      });
      const v=candidates[0],id=crypto.randomUUID(),now=new Date().toISOString();
      rows.push([id,eventId,s.id,v.id,0,0,0,0,now,now]);
      assigned.push({id,slot_id:s.id,volunteer_id:v.id,date:s.date,start_time:s.start_time,end_time:s.end_time,task_name:s.task_name});
      record(v.id,s);
    }
  }

  // D1 batch is used for the replacement so delete + inserts succeed together.
  const statements:D1PreparedStatement[]=[departmentId?env.DB.prepare(`DELETE FROM assignments WHERE event_id=? AND locked=0 AND slot_id IN (SELECT s.id FROM slots s JOIN tasks t ON t.id=s.task_id WHERE s.event_id=? AND t.department_id=?)`).bind(eventId,eventId,departmentId):env.DB.prepare(`DELETE FROM assignments WHERE event_id=? AND locked=0`).bind(eventId)];
  for(const r of rows)statements.push(env.DB.prepare(`INSERT INTO assignments(id,event_id,slot_id,volunteer_id,locked,published,email_sent,sms_sent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(...r));
  await env.DB.batch(statements);
  return json({ok:true,created:rows.length,unfilled});
}

async function setEntryLink(req:Request,env:Env,eventId:string){
  const e=await getEvent(env,eventId);if(!e)return nf('Event not found');
  const b=await body(req);if(!b)return bad('Invalid JSON');
  const departmentId=clean(b.department_id)||(await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(eventId).first<{id:string}>())?.id||'';
  if(!departmentId)return bad('Create a department first.');
  const dep=await env.DB.prepare(`SELECT id,name FROM departments WHERE id=? AND event_id=?`).bind(departmentId,eventId).first<{id:string,name:string}>();if(!dep)return bad('Department not found.');
  const enabled=b.enabled!==false,now=new Date().toISOString();
  if(!enabled){await env.DB.prepare(`UPDATE department_entry_links SET enabled=0,updated_at=? WHERE event_id=? AND department_id=?`).bind(now,eventId,departmentId).run();return json({ok:true,enabled:false});}
  const token=tokenString(),hash=await tokenHash(token);
  const existing=await env.DB.prepare(`SELECT short_code FROM department_entry_links WHERE event_id=? AND department_id=?`).bind(eventId,departmentId).first<{short_code:string|null}>();
  // Normal enable/copy operations preserve the department's stable short URL. An explicit
  // rotate request creates a new short code and immediately invalidates the previous one.
  const shortCode=(b.rotate===true||!existing?.short_code)?shortCodeString():existing.short_code;
  await env.DB.prepare(`INSERT INTO department_entry_links(id,event_id,department_id,token_hash,short_code,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(event_id,department_id) DO UPDATE SET token_hash=excluded.token_hash,short_code=excluded.short_code,enabled=1,updated_at=excluded.updated_at`).bind(crypto.randomUUID(),eventId,departmentId,hash,shortCode,now,now).run();
  const origin=new URL(req.url).origin;
  return json({ok:true,enabled:true,department:dep,url:`${origin}/entry/${token}`,short_url:`${origin}/e/${shortCode}`,short_code:shortCode});
}
async function entryContext(env:Env,token:string){
  if(!token||token.length<20)return null;const hash=await tokenHash(token);
  const x=await env.DB.prepare(`SELECT e.id event_id,e.name,e.start_date,e.end_date,d.id department_id,d.name department_name FROM department_entry_links l JOIN events e ON e.id=l.event_id JOIN departments d ON d.id=l.department_id WHERE l.enabled=1 AND l.token_hash=? AND d.active=1`).bind(hash).first<any>();
  if(x)return x;
  // Backward compatibility for entry links created before departments were introduced.
  const e=await env.DB.prepare(`SELECT id event_id,name,start_date,end_date FROM events WHERE entry_enabled=1 AND entry_token_hash=?`).bind(hash).first<any>();if(!e)return null;
  const d=await env.DB.prepare(`SELECT id department_id,name department_name FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(e.event_id).first<any>();return d?{...e,...d}:null;
}
async function entryData(env:Env,token:string){const x=await entryContext(env,token);if(!x)return nf('This volunteer entry link is not valid or has been disabled.');return json({ok:true,event:{name:x.name,start_date:x.start_date,end_date:x.end_date,department_name:x.department_name}})}
async function shortEntryContext(env:Env,code:string){
  if(!/^[A-Za-z0-9]{8}$/.test(code))return null;
  return env.DB.prepare(`SELECT e.id event_id,e.name,e.start_date,e.end_date,d.id department_id,d.name department_name FROM department_entry_links l JOIN events e ON e.id=l.event_id JOIN departments d ON d.id=l.department_id WHERE l.enabled=1 AND l.short_code=? AND d.active=1`).bind(code).first<any>();
}
async function shortEntryData(env:Env,code:string){const x=await shortEntryContext(env,code);if(!x)return nf('This volunteer entry link is not valid or has been disabled.');return json({ok:true,event:{name:x.name,start_date:x.start_date,end_date:x.end_date,department_name:x.department_name}})}
async function addEntryForContext(req:Request,env:Env,x:any){
  const b=await body(req);if(!b)return bad('Invalid JSON');
  const rawList=Array.isArray(b.volunteers)?b.volunteers:[b];if(!rawList.length)return bad('No volunteers supplied');if(rawList.length>500)return bad('Too many volunteers in one request');
  const parsed:any[]=[];for(let i=0;i<rawList.length;i++){const raw=rawList[i];if(!raw||typeof raw!=='object')return bad('Invalid volunteer row');const p=parseVolunteer(raw as Record<string,unknown>);if('error'in p)return bad(p.error);if(!p.value.email||!p.value.phone)return bad(rawList.length>1?`Row ${i+1}: Email and phone number are required`:'Email and phone number are required');parsed.push(p.value)}
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];for(const v of parsed){const id=crypto.randomUUID();stmts.push(env.DB.prepare(`INSERT INTO volunteers(id,event_id,first_name,last_name,gender,email,phone,family,active,created_at,updated_at,department_id) VALUES(?,?,?,?,?,?,?,?,1,?,?,?)`).bind(id,x.event_id,v.first,v.last,v.gender,v.email||null,v.phone||null,v.family||null,now,now,x.department_id));for(const role of v.roles)stmts.push(env.DB.prepare(`INSERT INTO volunteer_roles(volunteer_id,role) VALUES(?,?)`).bind(id,role))}
  if(stmts.length)await env.DB.batch(stmts);return json({ok:true,count:parsed.length,department:x.department_name});
}
async function shortEntryAdd(req:Request,env:Env,code:string){const x=await shortEntryContext(env,code);if(!x)return nf('This volunteer entry link is not valid or has been disabled.');return addEntryForContext(req,env,x)}
async function entryAdd(req:Request,env:Env,token:string){
  const x=await entryContext(env,token);if(!x)return nf('This volunteer entry link is not valid or has been disabled.');return addEntryForContext(req,env,x);
}
function entryShell(){
 return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>OurPortal — Volunteer Entry</title><link rel="stylesheet" href="/app.css"></head>
<body class="confirmation-page"><main class="confirmation-wrap"><div id="entry-app" class="confirmation-public-card"><div class="loading">Loading volunteer entry…</div></div></main>
<script>
const token=decodeURIComponent(location.pathname.split('/').pop()||''),shortMode=location.pathname.startsWith('/e/'),apiBase=shortMode?'/api/e/':'/api/entry/',app=document.getElementById('entry-app');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function call(url,opt){const r=await fetch(url,opt),j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||'Request failed');return j}
function form(e){app.innerHTML='<div class="confirmation-hero"><div class="eyebrow">Volunteer Entry</div><h1>'+esc(e.name)+'</h1><div class="muted">'+esc(e.start_date)+(e.end_date!==e.start_date?' – '+esc(e.end_date):'')+(e.department_name?' · '+esc(e.department_name):'')+'</div></div><div class="confirmation-body"><div class="entry-tabs"><button id="one-tab" class="primary">Add One</button><button id="bulk-tab" class="secondary">Bulk Add</button></div><div id="entry-body"></div></div>';one();app.querySelector('#one-tab').onclick=one;app.querySelector('#bulk-tab').onclick=bulk}
function one(){app.querySelector('#one-tab').className='primary';app.querySelector('#bulk-tab').className='secondary';app.querySelector('#entry-body').innerHTML='<form id="one-form" class="entry-form"><div class="date-grid"><label>First Name<input id="fn" required></label><label>Last Name<input id="ln" required></label></div><label>Gender<select id="gender" required><option value="">Select gender</option><option>Male</option><option>Female</option></select></label><div class="date-grid"><label>Email<input id="email" type="email" required></label><label>Phone<input id="phone" type="tel" required></label></div><button class="primary">Add Volunteer</button><div id="msg" class="form-error"></div></form>';app.querySelector('#one-form').onsubmit=saveOne}
async function saveOne(ev){ev.preventDefault();const b=ev.submitter;b.disabled=true;b.textContent='Adding…';try{await call(apiBase+encodeURIComponent(token),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({first_name:fn.value,last_name:ln.value,gender:gender.value,email:email.value,phone:phone.value,roles:[]})});ev.target.reset();msg.className='confirmation-saved';msg.textContent='Volunteer added successfully.'}catch(e){msg.className='form-error';msg.textContent=e.message}finally{b.disabled=false;b.textContent='Add Volunteer'}}
function bulk(){app.querySelector('#one-tab').className='secondary';app.querySelector('#bulk-tab').className='primary';app.querySelector('#entry-body').innerHTML='<form id="bulk-form" class="entry-form"><p class="muted">Paste rows from Excel or Google Sheets: First Name | Last Name | Gender | Email | Phone</p><textarea id="bulk" rows="10" placeholder="John&#9;Smith&#9;Male&#9;john@example.com&#9;2065550101"></textarea><button class="primary">Add Volunteers</button><div id="bmsg" class="form-error"></div></form>';app.querySelector('#bulk-form').onsubmit=saveBulk}
async function saveBulk(ev){ev.preventDefault();const rows=bulk.value.split(/\\r?\\n/).filter(x=>x.trim()).map(line=>{const c=line.includes('\\t')?line.split('\\t'):line.split(',');return{first_name:(c[0]||'').trim(),last_name:(c[1]||'').trim(),gender:(c[2]||'').trim(),email:(c[3]||'').trim(),phone:(c[4]||'').trim(),roles:[]}});if(!rows.length){bmsg.textContent='Paste at least one row.';return}const b=ev.submitter;b.disabled=true;b.textContent='Adding…';try{const r=await call(apiBase+encodeURIComponent(token),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({volunteers:rows})});bulk.value='';bmsg.className='confirmation-saved';bmsg.textContent=r.count+' volunteer(s) added successfully.'}catch(e){bmsg.className='form-error';bmsg.textContent=e.message}finally{b.disabled=false;b.textContent='Add Volunteers'}}
call(apiBase+encodeURIComponent(token)).then(r=>form(r.event)).catch(e=>app.innerHTML='<div class="confirmation-body"><h2>Unable to open volunteer entry</h2><p>'+esc(e.message)+'</p></div>');
</script></body></html>`,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'}});
}
function tokenString(){
  const b=new Uint8Array(32);crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function shortCodeString(){
  const chars='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789',b=new Uint8Array(8);crypto.getRandomValues(b);
  return Array.from(b,x=>chars[x%chars.length]).join('');
}
async function tokenHash(token:string){
  const d=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token));
  return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function ensureConfirmationRows(env:Env,eventId:string){
  const now=new Date().toISOString();
  const rows=await env.DB.prepare(`SELECT id,volunteer_id FROM assignments WHERE event_id=?`).bind(eventId).all<any>();
  if(rows.results.length)await env.DB.batch(rows.results.map(a=>env.DB.prepare(`
    INSERT OR IGNORE INTO confirmations(assignment_id,event_id,volunteer_id,status,responded_at,note,created_at,updated_at)
    VALUES(?,?,?,'Awaiting',NULL,NULL,?,?)
  `).bind(a.id,eventId,a.volunteer_id,now,now)));
}
async function confirmationDashboard(env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  await ensureConfirmationRows(env,eventId);
  const r=await env.DB.prepare(`
    SELECT a.id assignment_id,a.volunteer_id,v.first_name,v.last_name,v.email,v.phone,
           s.date,s.start_time,s.end_time,t.name task_name,
           COALESCE(c.status,'Awaiting') status,c.responded_at,c.note,
           CASE WHEN cl.token_hash IS NULL THEN 0 ELSE 1 END has_link,
           cl.first_viewed_at,cl.last_viewed_at,COALESCE(cl.view_count,0) view_count
    FROM assignments a
    JOIN volunteers v ON v.id=a.volunteer_id
    JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id
    LEFT JOIN confirmations c ON c.assignment_id=a.id
    LEFT JOIN confirmation_links cl ON cl.event_id=a.event_id AND cl.volunteer_id=a.volunteer_id
    WHERE a.event_id=?
    ORDER BY v.last_name,v.first_name,s.date,s.start_time,t.name
  `).bind(eventId).all<any>();
  const by:Record<string,any>={};
  for(const x of r.results){
    if(!by[x.volunteer_id])by[x.volunteer_id]={volunteer_id:x.volunteer_id,volunteer_name:`${x.first_name} ${x.last_name}`.trim(),email:x.email||'',phone:x.phone||'',has_link:!!x.has_link,first_viewed_at:x.first_viewed_at||'',last_viewed_at:x.last_viewed_at||'',view_count:Number(x.view_count||0),assignments:[]};
    by[x.volunteer_id].assignments.push({assignment_id:x.assignment_id,date:x.date,start_time:x.start_time,end_time:x.end_time,task_name:x.task_name,status:x.status,responded_at:x.responded_at||'',note:x.note||''});
  }
  const volunteers=Object.values(by).map((v:any)=>{
    const s=v.assignments.map((a:any)=>a.status);
    v.overall_status=s.length&&s.every((x:string)=>x==='Accepted')?'Confirmed All':
      s.some((x:string)=>x==='Declined')?(s.some((x:string)=>x==='Accepted')?'Partial':'Conflict'):
      s.some((x:string)=>x==='Accepted')?'Partial':'Awaiting';
    return v;
  });
  return json({ok:true,volunteers});
}
async function generateConfirmationLinks(request:Request,env:Env,eventId:string){
  if(!await getEvent(env,eventId))return nf('Event not found');
  await ensureConfirmationRows(env,eventId);
  const vols=await env.DB.prepare(`SELECT DISTINCT a.volunteer_id,v.first_name,v.last_name FROM assignments a JOIN volunteers v ON v.id=a.volunteer_id WHERE a.event_id=? ORDER BY v.last_name,v.first_name`).bind(eventId).all<any>();
  const now=new Date().toISOString(),origin=new URL(request.url).origin,links:any[]=[];
  const stmts:D1PreparedStatement[]=[];
  for(const v of vols.results){
    const token=tokenString(),hash=await tokenHash(token);
    stmts.push(env.DB.prepare(`INSERT INTO confirmation_links(event_id,volunteer_id,token_hash,created_at,updated_at) VALUES(?,?,?,?,?)
      ON CONFLICT(event_id,volunteer_id) DO UPDATE SET token_hash=excluded.token_hash,updated_at=excluded.updated_at`).bind(eventId,v.volunteer_id,hash,now,now));
    links.push({volunteer_id:v.volunteer_id,volunteer_name:`${v.first_name} ${v.last_name}`.trim(),url:`${origin}/confirm/${token}`});
  }
  if(stmts.length)await env.DB.batch(stmts);
  return json({ok:true,links});
}
function b64urlText(v:string){
 const bytes=new TextEncoder().encode(v);let raw='';for(const b of bytes)raw+=String.fromCharCode(b);return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function emailSafe(v:string){return v.replace(/[\r\n]+/g,' ').trim()}
async function gmailAccessToken(env:Env){
 if(!env.GMAIL_CLIENT_ID||!env.GMAIL_CLIENT_SECRET||!env.GMAIL_REFRESH_TOKEN)throw new Error('Gmail sender is not configured.');
 const form=new URLSearchParams({client_id:env.GMAIL_CLIENT_ID,client_secret:env.GMAIL_CLIENT_SECRET,refresh_token:env.GMAIL_REFRESH_TOKEN,grant_type:'refresh_token'});
 const r=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form});
 const j=await r.json<any>();if(!r.ok||!j.access_token)throw new Error('Unable to authorize the configured Gmail sender.');return String(j.access_token);
}
async function gmailSend(env:Env,to:string,subject:string,textBody:string,htmlBody:string){
 const access=await gmailAccessToken(env),from=emailSafe(env.GMAIL_FROM||'rccainv@gmail.com');
 const boundary='ourportal_'+crypto.randomUUID().replace(/-/g,'');
 const mime=[`From: ${from}`,`To: ${emailSafe(to)}`,`Subject: ${emailSafe(subject)}`,'MIME-Version: 1.0',`Content-Type: multipart/alternative; boundary="${boundary}"`,'',`--${boundary}`,'Content-Type: text/plain; charset="UTF-8"','Content-Transfer-Encoding: 8bit','',textBody,'',`--${boundary}`,'Content-Type: text/html; charset="UTF-8"','Content-Transfer-Encoding: 8bit','',htmlBody,'',`--${boundary}--`].join('\r\n');
 const r=await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',{method:'POST',headers:{authorization:`Bearer ${access}`,'content-type':'application/json'},body:JSON.stringify({raw:b64urlText(mime)})});
 const j=await r.json<any>();if(!r.ok)throw new Error(j?.error?.message||'Gmail rejected the message.');return String(j.id||'');
}
async function gmailSendPlain(env:Env,to:string,subject:string,textBody:string){
 const access=await gmailAccessToken(env),from=emailSafe(env.GMAIL_FROM||'rccainv@gmail.com');
 const mime=[`From: ${from}`,`To: ${emailSafe(to)}`,`Subject: ${emailSafe(subject)}`,'MIME-Version: 1.0','Content-Type: text/plain; charset="UTF-8"','Content-Transfer-Encoding: 8bit','',textBody].join('\r\n');
 const r=await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',{method:'POST',headers:{authorization:`Bearer ${access}`,'content-type':'application/json'},body:JSON.stringify({raw:b64urlText(mime)})});
 const j=await r.json<any>();if(!r.ok)throw new Error(j?.error?.message||'Gmail rejected the message.');return String(j.id||'');
}
function htmlEsc(v:string){return v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]||c))}
async function sendScheduleEmails(request:Request,env:Env,eventId:string){
 const event=await getEvent(env,eventId);if(!event)return nf('Event not found');
 const b=await body(request)||{},kind=clean(b.kind)==='Reminder'?'Reminder':'Schedule',mode=clean(b.mode)==='Plain'?'Plain':'Link';
 const selected=Array.isArray(b.volunteer_ids)?new Set(b.volunteer_ids.map(clean).filter(Boolean)):null;
 await ensureConfirmationRows(env,eventId);
 const rows=await env.DB.prepare(`SELECT a.volunteer_id,v.first_name,v.last_name,v.email,s.date,s.start_time,s.end_time,t.name task_name,COALESCE(c.status,'Awaiting') status FROM assignments a JOIN volunteers v ON v.id=a.volunteer_id JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id LEFT JOIN confirmations c ON c.assignment_id=a.id WHERE a.event_id=? ORDER BY v.last_name,v.first_name,s.date,s.start_time,t.name`).bind(eventId).all<any>();
 const by:Record<string,any>={};for(const x of rows.results){if(!by[x.volunteer_id])by[x.volunteer_id]={id:x.volunteer_id,name:`${x.first_name} ${x.last_name}`.trim(),email:x.email||'',assignments:[]};by[x.volunteer_id].assignments.push(x)}
 const origin=new URL(request.url).origin,now=new Date().toISOString(),results:any[]=[];
 for(const v of Object.values(by) as any[]){
  if(selected&&!selected.has(v.id))continue;if(kind==='Reminder'&&!v.assignments.some((a:any)=>a.status==='Awaiting'))continue;
  if(!v.email){results.push({volunteer_id:v.id,name:v.name,status:'Skipped',error:'No email address'});continue}
  let link='';
  if(mode==='Link'){
   const token=tokenString(),hash=await tokenHash(token);await env.DB.prepare(`INSERT INTO confirmation_links(event_id,volunteer_id,token_hash,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(event_id,volunteer_id) DO UPDATE SET token_hash=excluded.token_hash,updated_at=excluded.updated_at`).bind(eventId,v.id,hash,now,now).run();
   link=`${origin}/confirm/${token}`;
  }
  const subject=kind==='Reminder'?`Reminder: Your volunteer schedule for ${event.name}`:`Your volunteer schedule for ${event.name}`;
  const lines=v.assignments.map((a:any)=>`${a.date} · ${a.start_time}${a.end_time?'–'+a.end_time:''} · ${a.task_name}`).join('\n');
  const intro=kind==='Reminder'?`This is a reminder of your volunteer schedule for ${event.name}.`:`Your volunteer schedule for ${event.name}:`;
  const textBody=mode==='Link'?`Hello ${v.name},\n\n${intro}\n\n${lines}\n\nReview and confirm your assignments:\n${link}\n\nThank you.`:`Hello ${v.name},\n\n${intro}\n\n${lines}\n\nThank you.`;
  const items=v.assignments.map((a:any)=>`<li><strong>${htmlEsc(a.task_name)}</strong> — ${htmlEsc(a.date)} · ${htmlEsc(a.start_time)}${a.end_time?'–'+htmlEsc(a.end_time):''}</li>`).join('');
  const htmlBody=`<p>Hello ${htmlEsc(v.name)},</p><p>${htmlEsc(intro)}</p><ul>${items}</ul><p><a href="${htmlEsc(link)}">Review and confirm your assignments</a></p><p>Thank you.</p>`;
  try{const provider=mode==='Plain'?await gmailSendPlain(env,v.email,subject,textBody):await gmailSend(env,v.email,subject,textBody,htmlBody);await env.DB.prepare(`INSERT INTO communication_log(id,event_id,volunteer_id,channel,kind,status,provider_id,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),eventId,v.id,'Email',`${kind} ${mode}`,'Sent',provider,now).run();results.push({volunteer_id:v.id,name:v.name,status:'Sent'})}
  catch(e:any){await env.DB.prepare(`INSERT INTO communication_log(id,event_id,volunteer_id,channel,kind,status,provider_id,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),eventId,v.id,'Email',`${kind} ${mode}`,'Failed',null,now).run();results.push({volunteer_id:v.id,name:v.name,status:'Failed',error:e?.message||'Send failed'})}
 }
 return json({ok:true,kind,mode,sent:results.filter(x=>x.status==='Sent').length,failed:results.filter(x=>x.status==='Failed').length,skipped:results.filter(x=>x.status==='Skipped').length,results});
}
async function prepareScheduleSms(request:Request,env:Env,eventId:string){
 const event=await getEvent(env,eventId);if(!event)return nf('Event not found');
 const b=await body(request)||{},kind=clean(b.kind)==='Reminder'?'Reminder':'Schedule',mode=clean(b.mode)==='Plain'?'Plain':'Link';
 const selected=Array.isArray(b.volunteer_ids)?new Set(b.volunteer_ids.map(clean).filter(Boolean)):null;
 await ensureConfirmationRows(env,eventId);
 const rows=await env.DB.prepare(`SELECT a.volunteer_id,v.first_name,v.last_name,v.phone,s.date,s.start_time,s.end_time,t.name task_name,COALESCE(c.status,'Awaiting') status FROM assignments a JOIN volunteers v ON v.id=a.volunteer_id JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id LEFT JOIN confirmations c ON c.assignment_id=a.id WHERE a.event_id=? ORDER BY v.last_name,v.first_name,s.date,s.start_time,t.name`).bind(eventId).all<any>();
 const by:Record<string,any>={};for(const x of rows.results){if(!by[x.volunteer_id])by[x.volunteer_id]={id:x.volunteer_id,name:`${x.first_name} ${x.last_name}`.trim(),phone:x.phone||'',assignments:[]};by[x.volunteer_id].assignments.push(x)}
 const origin=new URL(request.url).origin,now=new Date().toISOString(),messages:any[]=[];
 for(const v of Object.values(by) as any[]){
  if(selected&&!selected.has(v.id))continue;if(kind==='Reminder'&&!v.assignments.some((a:any)=>a.status==='Awaiting'))continue;if(!v.phone)continue;
  let link='';if(mode==='Link'){const token=tokenString(),hash=await tokenHash(token);await env.DB.prepare(`INSERT INTO confirmation_links(event_id,volunteer_id,token_hash,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(event_id,volunteer_id) DO UPDATE SET token_hash=excluded.token_hash,updated_at=excluded.updated_at`).bind(eventId,v.id,hash,now,now).run();link=`${origin}/confirm/${token}`}
  const lines=v.assignments.map((a:any)=>`${a.date} ${a.start_time}${a.end_time?'-'+a.end_time:''} ${a.task_name}`).join('; ');
  const lead=kind==='Reminder'?`Reminder — ${event.name}:`:`${event.name}:`;
  const message=mode==='Link'?`${lead} ${lines}. Confirm: ${link}`:`${lead} ${lines}.`;
  messages.push({volunteer_id:v.id,name:v.name,phone:v.phone,message});
  await env.DB.prepare(`INSERT INTO communication_log(id,event_id,volunteer_id,channel,kind,status,provider_id,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),eventId,v.id,'SMS',`${kind} ${mode}`,'Prepared',null,now).run();
 }
 return json({ok:true,kind,mode,count:messages.length,messages});
}
async function manualConfirmation(request:Request,env:Env,eventId:string,volunteerId:string){
 if(!await getEvent(env,eventId))return nf('Event not found');
 const b=await body(request)||{},status=clean(b.status);if(!['Awaiting','Accepted','Declined'].includes(status))return bad('Choose Awaiting, Accepted, or Declined.');
 const rows=await env.DB.prepare(`SELECT id FROM assignments WHERE event_id=? AND volunteer_id=?`).bind(eventId,volunteerId).all<any>();if(!rows.results.length)return nf('No assignments found for this volunteer.');
 const now=new Date().toISOString(),responded=status==='Awaiting'?null:now,note=status==='Awaiting'?'':'Manually updated in portal';
 await env.DB.batch(rows.results.map(a=>env.DB.prepare(`INSERT INTO confirmations(assignment_id,event_id,volunteer_id,status,responded_at,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(assignment_id) DO UPDATE SET status=excluded.status,responded_at=excluded.responded_at,note=excluded.note,updated_at=excluded.updated_at`).bind(a.id,eventId,volunteerId,status,responded,note,now,now)));
 return json({ok:true,status,updated:rows.results.length});
}
async function communicationHistory(env:Env,eventId:string){
 const r=await env.DB.prepare(`SELECT c.volunteer_id,c.kind,c.status,c.created_at,v.first_name,v.last_name FROM communication_log c LEFT JOIN volunteers v ON v.id=c.volunteer_id WHERE c.event_id=? AND c.channel='Email' ORDER BY c.created_at DESC LIMIT 500`).bind(eventId).all<any>();return json({ok:true,communications:r.results});
}
async function confirmationPageData(env:Env,token:string){
  if(!token||token.length<20)return bad('This confirmation link is invalid.');
  const hash=await tokenHash(token);
  const link=await env.DB.prepare(`SELECT event_id,volunteer_id FROM confirmation_links WHERE token_hash=?`).bind(hash).first<{event_id:string,volunteer_id:string}>();
  if(!link)return new Response(JSON.stringify({ok:false,error:'This confirmation link is invalid or no longer active.'}),{status:404,headers:{'content-type':'application/json'}});
  const viewedNow=new Date().toISOString();
  await env.DB.prepare(`UPDATE confirmation_links SET first_viewed_at=COALESCE(first_viewed_at,?),last_viewed_at=?,view_count=COALESCE(view_count,0)+1,updated_at=? WHERE token_hash=?`).bind(viewedNow,viewedNow,viewedNow,hash).run();
  await ensureConfirmationRows(env,link.event_id);
  const event=await env.DB.prepare(`SELECT name,start_date,end_date FROM events WHERE id=?`).bind(link.event_id).first<any>();
  const volunteer=await env.DB.prepare(`SELECT first_name,last_name FROM volunteers WHERE id=? AND event_id=?`).bind(link.volunteer_id,link.event_id).first<any>();
  const rows=await env.DB.prepare(`
    SELECT a.id assignment_id,s.date,s.start_time,s.end_time,t.name task_name,
           COALESCE(c.status,'Awaiting') status,c.responded_at,c.note
    FROM assignments a JOIN slots s ON s.id=a.slot_id JOIN tasks t ON t.id=s.task_id
    LEFT JOIN confirmations c ON c.assignment_id=a.id
    WHERE a.event_id=? AND a.volunteer_id=?
    ORDER BY s.date,s.start_time,t.name
  `).bind(link.event_id,link.volunteer_id).all<any>();
  return json({ok:true,event_name:event?.name||'Volunteer Schedule',start_date:event?.start_date||'',end_date:event?.end_date||'',volunteer_name:volunteer?`${volunteer.first_name} ${volunteer.last_name}`.trim():'Volunteer',assignments:rows.results});
}
async function saveConfirmationResponses(req:Request,env:Env,token:string){
  const hash=await tokenHash(token);
  const link=await env.DB.prepare(`SELECT event_id,volunteer_id FROM confirmation_links WHERE token_hash=?`).bind(hash).first<{event_id:string,volunteer_id:string}>();
  if(!link)return nf('This confirmation link is invalid or no longer active.');
  const b=await body(req);if(!b||!Array.isArray(b.responses)||!b.responses.length)return bad('Choose Accept or Decline for at least one assignment.');
  const now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];
  for(const x of b.responses){
    const id=clean(x?.assignment_id),status=clean(x?.status);
    if(!id||!['Accepted','Declined'].includes(status))return bad('Invalid confirmation response.');
    const own=await env.DB.prepare(`SELECT id FROM assignments WHERE id=? AND event_id=? AND volunteer_id=?`).bind(id,link.event_id,link.volunteer_id).first();
    if(!own)return bad('One of the selected assignments is not valid for this confirmation link.');
    stmts.push(env.DB.prepare(`INSERT INTO confirmations(assignment_id,event_id,volunteer_id,status,responded_at,note,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?)
      ON CONFLICT(assignment_id) DO UPDATE SET status=excluded.status,responded_at=excluded.responded_at,note=excluded.note,updated_at=excluded.updated_at`)
      .bind(id,link.event_id,link.volunteer_id,status,now,'',now,now));
  }
  await env.DB.batch(stmts);
  return json({ok:true,saved:stmts.length});
}
function confirmationShell(){
 return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>OurPortal — Schedule Confirmation</title><link rel="stylesheet" href="/app.css"></head>
<body class="confirmation-page"><main class="confirmation-wrap"><div id="confirmation-app" class="confirmation-public-card"><div class="loading">Loading your schedule…</div></div></main>
<script>
const token=decodeURIComponent(location.pathname.split('/').pop()||''),app=document.getElementById('confirmation-app');let data,pending={};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time=s=>{if(!s)return'';let [h,m]=s.split(':').map(Number),ap=h>=12?'PM':'AM';h=h%12||12;return h+':'+String(m).padStart(2,'0')+' '+ap};
async function call(url,opt){const r=await fetch(url,opt);const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||'Request failed');return j}
function draw(){
 const accepted=data.assignments.filter(a=>a.status==='Accepted').length,declined=data.assignments.filter(a=>a.status==='Declined').length,waiting=data.assignments.length-accepted-declined;
 app.innerHTML='<div class="confirmation-hero"><div class="eyebrow">Volunteer Schedule</div><h1>'+esc(data.event_name)+'</h1><div class="muted">'+esc(data.start_date)+(data.end_date&&data.end_date!==data.start_date?' – '+esc(data.end_date):'')+'</div></div><div class="confirmation-body"><h2>Hello '+esc(data.volunteer_name)+',</h2><p class="confirmation-help">Review your assignments, choose Accept or Decline, then select Confirm Responses.</p><div class="confirmation-summary-public"><span>✓ '+accepted+' accepted</span><span>'+waiting+' awaiting</span><span>'+declined+' declined</span></div>'+data.assignments.map(a=>{const choice=pending[a.assignment_id]||a.status;return '<article class="public-assignment"><div><strong>'+esc(a.task_name)+'</strong><div class="muted">'+esc(a.date)+' · '+time(a.start_time)+(a.end_time?' – '+time(a.end_time):'')+'</div></div><div class="response-buttons"><button class="accept-choice '+(choice==='Accepted'?'selected':'')+'" data-id="'+esc(a.assignment_id)+'" data-choice="Accepted">✓ Accept</button><button class="decline-choice '+(choice==='Declined'?'selected':'')+'" data-id="'+esc(a.assignment_id)+'" data-choice="Declined">Decline</button></div></article>'}).join('')+'<button id="submit-responses" class="primary confirmation-submit">Confirm Responses</button><div id="confirmation-msg" class="form-error"></div></div>';
 app.querySelectorAll('[data-choice]').forEach(b=>b.onclick=()=>{pending[b.dataset.id]=b.dataset.choice;draw()});
 app.querySelector('#submit-responses').onclick=submit;
}
async function load(){try{data=await call('/api/confirm/'+encodeURIComponent(token));draw()}catch(e){app.innerHTML='<div class="confirmation-body"><h2>Unable to open confirmation</h2><p>'+esc(e.message)+'</p></div>'}}
async function submit(){const responses=Object.entries(pending).map(([assignment_id,status])=>({assignment_id,status}));if(!responses.length){app.querySelector('#confirmation-msg').textContent='Choose Accept or Decline for at least one assignment.';return}const b=app.querySelector('#submit-responses');b.disabled=true;b.textContent='Saving…';try{await call('/api/confirm/'+encodeURIComponent(token),{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({responses})});pending={};data=await call('/api/confirm/'+encodeURIComponent(token));draw();const m=document.createElement('div');m.className='confirmation-saved';m.textContent='Your responses have been saved.';app.querySelector('.confirmation-body').prepend(m)}catch(e){b.disabled=false;b.textContent='Confirm Responses';app.querySelector('#confirmation-msg').textContent=e.message}}
load();
</script></body></html>`,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'}});
}

async function listEventPeople(env:Env,eventId:string){
 if(!await getEvent(env,eventId))return nf('Event not found');
 const r=await env.DB.prepare(`SELECT id,event_id,first_name,last_name,email,phone,active,created_at,updated_at FROM event_people WHERE event_id=? ORDER BY active DESC,last_name COLLATE NOCASE,first_name COLLATE NOCASE`).bind(eventId).all<any>();
 return json({ok:true,people:r.results});
}
async function saveEventPerson(req:Request,env:Env,eventId:string,id=''){
 if(!await getEvent(env,eventId))return nf('Event not found');const b=await body(req);if(!b)return bad('Invalid JSON');
 const first=clean(b.first_name),last=clean(b.last_name),email=clean(b.email)||null,phone=clean(b.phone)||null;if(!first||!last)return bad('First and last name are required.');const now=new Date().toISOString();
 if(id){const r=await env.DB.prepare(`UPDATE event_people SET first_name=?,last_name=?,email=?,phone=?,active=?,updated_at=? WHERE id=? AND event_id=?`).bind(first,last,email,phone,b.active===false?0:1,now,id,eventId).run();if(!r.meta.changes)return nf('Person not found');return json({ok:true,id});}
 id=crypto.randomUUID();await env.DB.prepare(`INSERT INTO event_people(id,event_id,first_name,last_name,email,phone,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`).bind(id,eventId,first,last,email,phone,now,now).run();return json({ok:true,id},201);
}
async function deleteEventPerson(env:Env,eventId:string,id:string){
 const used=await env.DB.prepare(`SELECT COUNT(*) c FROM org_nodes WHERE event_id=? AND person_id=?`).bind(eventId,id).first<{c:number}>();if(Number(used?.c||0)>0)return bad('This person is assigned in the organization. Change or remove that assignment first.');
 const r=await env.DB.prepare(`DELETE FROM event_people WHERE id=? AND event_id=?`).bind(id,eventId).run();if(!r.meta.changes)return nf('Person not found');return json({ok:true});
}
async function deleteEvent(req:Request,env:Env,id:string){
 const e=await getEvent(env,id);if(!e)return nf('Event not found');const b=await body(req);if(!b)return bad('Invalid JSON');if(clean(b.confirm_name)!==e.name)return bad('Type the exact event name to permanently delete it.');
 await env.DB.prepare(`UPDATE departments SET committee_node_id=NULL WHERE event_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM events WHERE id=?`).bind(id).run();return json({ok:true,deleted:id});
}

async function organizationData(env:Env,eventId:string){
 const event=await getEvent(env,eventId);if(!event)return nf('Event not found');
 if(event.structure_mode==='Full')await ensureFullCommitteePositions(env,eventId);
 const [d,a,n,p]=await Promise.all([
  env.DB.prepare(`SELECT d.*, (SELECT COUNT(*) FROM volunteers v WHERE v.event_id=d.event_id AND v.department_id=d.id) volunteer_count,(SELECT COUNT(*) FROM tasks t WHERE t.event_id=d.event_id AND t.department_id=d.id) task_count,(SELECT COUNT(*) FROM slots s JOIN tasks t ON t.id=s.task_id WHERE t.event_id=d.event_id AND t.department_id=d.id) slot_count,(SELECT l.short_code FROM department_entry_links l WHERE l.event_id=d.event_id AND l.department_id=d.id AND l.enabled=1) entry_short_code,(SELECT l.enabled FROM department_entry_links l WHERE l.event_id=d.event_id AND l.department_id=d.id) entry_link_enabled FROM departments d WHERE d.event_id=? ORDER BY d.sort_order,d.name`).bind(eventId).all<any>(),
  env.DB.prepare(`SELECT * FROM assistant_areas WHERE event_id=? ORDER BY department_id,sort_order,label`).bind(eventId).all<any>(),
  env.DB.prepare(`SELECT n.*,COALESCE(p.first_name,v.first_name) first_name,COALESCE(p.last_name,v.last_name) last_name FROM org_nodes n LEFT JOIN event_people p ON p.id=n.person_id LEFT JOIN volunteers v ON v.id=n.volunteer_id WHERE n.event_id=? ORDER BY n.sort_order,n.node_type`).bind(eventId).all<any>(),
  env.DB.prepare(`SELECT id,event_id,first_name,last_name,email,phone,active FROM event_people WHERE event_id=? ORDER BY active DESC,last_name COLLATE NOCASE,first_name COLLATE NOCASE`).bind(eventId).all<any>()
 ]);return json({ok:true,departments:d.results,assistant_areas:a.results,nodes:n.results,people:p.results});
}
async function saveDepartment(req:Request,env:Env,eventId:string,id=''){
 if(!await getEvent(env,eventId))return nf('Event not found');const b=await body(req);if(!b)return bad('Invalid JSON');const name=clean(b.name);if(!name)return bad('Department name is required');const now=new Date().toISOString();
 const committeeNodeId=clean(b.committee_node_id)||null;
 if(committeeNodeId){const cm=await env.DB.prepare(`SELECT id FROM org_nodes WHERE id=? AND event_id=? AND node_type='Committee Member'`).bind(committeeNodeId,eventId).first();if(!cm)return bad('Committee member not found');}
 if(id){const r=await env.DB.prepare(`UPDATE departments SET name=?,active=?,committee_node_id=?,updated_at=? WHERE id=? AND event_id=?`).bind(name,b.active===false?0:1,committeeNodeId,now,id,eventId).run();if(!r.meta.changes)return nf('Department not found');return json({ok:true,id});}
 id=crypto.randomUUID();await env.DB.prepare(`INSERT INTO departments(id,event_id,name,active,sort_order,created_at,updated_at,committee_node_id) VALUES(?,?,?,1,COALESCE((SELECT MAX(sort_order)+1 FROM departments WHERE event_id=?),0),?,?,?)`).bind(id,eventId,name,eventId,now,now,committeeNodeId).run();return json({ok:true,id},201);
}
async function deleteDepartment(req:Request,env:Env,eventId:string,id:string){
 const d=await env.DB.prepare(`SELECT id,name FROM departments WHERE id=? AND event_id=?`).bind(id,eventId).first<{id:string,name:string}>();
 if(!d)return nf('Department not found');
 const b=await body(req);if(!b)return bad('Invalid JSON');
 if(clean(b.confirm_name)!==d.name)return bad('Type the exact department name to permanently delete it.');
 const count=await env.DB.prepare(`SELECT COUNT(*) c FROM departments WHERE event_id=?`).bind(eventId).first<{c:number}>();
 if(Number(count?.c||0)<=1)return bad('An event must have at least one department. Create another department before deleting this one.');
 const volunteerIds=await env.DB.prepare(`SELECT id FROM volunteers WHERE event_id=? AND department_id=?`).bind(eventId,id).all<{id:string}>();
 const ids=volunteerIds.results.map(v=>v.id);
 const stmts:D1PreparedStatement[]=[];
 // Remove volunteer-scoped permissions that do not have a department foreign key.
 for(const volunteerId of ids)stmts.push(env.DB.prepare(`DELETE FROM app_permissions WHERE event_id=? AND scope_ref_id=? AND COALESCE(role,scope)='Volunteer'`).bind(eventId,volunteerId));
 // Communication history has no department_id; remove rows belonging to department volunteers before those volunteers are deleted.
 if(ids.length){for(const volunteerId of ids)stmts.push(env.DB.prepare(`DELETE FROM communication_log WHERE event_id=? AND volunteer_id=?`).bind(eventId,volunteerId));}
 // Tasks and volunteers reference departments with ON DELETE RESTRICT. Their child rows cascade from these deletes.
 stmts.push(env.DB.prepare(`DELETE FROM tasks WHERE event_id=? AND department_id=?`).bind(eventId,id));
 stmts.push(env.DB.prepare(`DELETE FROM volunteers WHERE event_id=? AND department_id=?`).bind(eventId,id));
 if(stmts.length)await env.DB.batch(stmts);
 // Department children (organization nodes, assistant areas, entry link and department-scoped permissions) cascade here.
 const r=await env.DB.prepare(`DELETE FROM departments WHERE id=? AND event_id=?`).bind(id,eventId).run();
 if(!r.meta.changes)return nf('Department not found');
 return json({ok:true,deleted:id,name:d.name});
}

async function saveArea(req:Request,env:Env,eventId:string){const b=await body(req);if(!b)return bad('Invalid JSON');const dep=clean(b.department_id),label=clean(b.label);if(!dep||!label)return bad('Department and Assistant label are required');const own=await env.DB.prepare(`SELECT id FROM departments WHERE id=? AND event_id=?`).bind(dep,eventId).first();if(!own)return bad('Department not found');const id=crypto.randomUUID(),now=new Date().toISOString();await env.DB.prepare(`INSERT INTO assistant_areas(id,event_id,department_id,label,person_volunteer_id,active,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,1,COALESCE((SELECT MAX(sort_order)+1 FROM assistant_areas WHERE department_id=?),0),?,?)`).bind(id,eventId,dep,label,clean(b.person_volunteer_id)||null,dep,now,now).run();return json({ok:true,id},201)}
async function saveOrgNode(req:Request,env:Env,eventId:string){
 const b=await body(req);if(!b)return bad('Invalid JSON');const typ=clean(b.node_type),allowed=['Committee Member','Committee Assistant','Department Overseer','Department Assistant','Keyman','Captain'];if(!allowed.includes(typ))return bad('Invalid organization role');
 const departmentId=clean(b.department_id)||null,parentId=clean(b.parent_id)||null,personId=clean(b.person_id)||null;if(!personId&&typ!=='Committee Member')return bad('Select a person.');if(personId){const person=await env.DB.prepare(`SELECT id FROM event_people WHERE id=? AND event_id=? AND active=1`).bind(personId,eventId).first();if(!person)return bad('Organizational volunteer not found for this event.');const duplicate=await env.DB.prepare(`SELECT id FROM org_nodes WHERE event_id=? AND node_type=? AND person_id=? AND COALESCE(department_id,'')=COALESCE(?,'') AND COALESCE(parent_id,'')=COALESCE(?,'')`).bind(eventId,typ,personId,departmentId,parentId).first();if(duplicate)return bad('This person is already assigned to this organization role.');}
 const id=crypto.randomUUID(),now=new Date().toISOString(),stmts:D1PreparedStatement[]=[];
 if(typ==='Department Overseer'&&departmentId)stmts.push(env.DB.prepare(`DELETE FROM org_nodes WHERE event_id=? AND department_id=? AND node_type='Department Overseer'`).bind(eventId,departmentId));
 if(typ==='Committee Assistant'&&parentId)stmts.push(env.DB.prepare(`DELETE FROM org_nodes WHERE event_id=? AND parent_id=? AND node_type='Committee Assistant'`).bind(eventId,parentId));
 stmts.push(env.DB.prepare(`INSERT INTO org_nodes(id,event_id,department_id,parent_id,node_type,label,person_id,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(id,eventId,departmentId,parentId,typ,clean(b.label)||null,personId,Number(b.sort_order)||0,now,now));await env.DB.batch(stmts);return json({ok:true,id},201)
}
async function patchOrgNode(req:Request,env:Env,eventId:string,id:string){
 const b=await body(req);if(!b)return bad('Invalid JSON');const n=await env.DB.prepare(`SELECT * FROM org_nodes WHERE id=? AND event_id=?`).bind(id,eventId).first<any>();if(!n)return nf('Organization position not found');
 const personId=clean(b.person_id)||null;if(personId){const p=await env.DB.prepare(`SELECT id FROM event_people WHERE id=? AND event_id=? AND active=1`).bind(personId,eventId).first();if(!p)return bad('Organizational volunteer not found for this event.');}
 await env.DB.prepare(`UPDATE org_nodes SET person_id=?,updated_at=? WHERE id=? AND event_id=?`).bind(personId,new Date().toISOString(),id,eventId).run();return json({ok:true,id});
}
async function moveVolunteer(req:Request,env:Env,eventId:string,volunteerId:string){const b=await body(req);if(!b)return bad('Invalid JSON');const dep=clean(b.department_id),area=clean(b.assistant_area_id)||null;const v=await env.DB.prepare(`SELECT id,department_id FROM volunteers WHERE id=? AND event_id=?`).bind(volunteerId,eventId).first<any>();if(!v)return nf('Volunteer not found');const d=await env.DB.prepare(`SELECT id FROM departments WHERE id=? AND event_id=?`).bind(dep,eventId).first();if(!d)return bad('Department not found');const c=await env.DB.prepare(`SELECT COUNT(*) c FROM assignments WHERE event_id=? AND volunteer_id=?`).bind(eventId,volunteerId).first<{c:number}>();if((c?.c||0)>0)return json({ok:false,error:'Volunteer has existing schedule assignments. Remove or reassign those assignments before moving this volunteer to another department.',assignments:c?.c||0,requires_resolution:true},409);await env.DB.prepare(`UPDATE volunteers SET department_id=?,assistant_area_id=?,updated_at=? WHERE id=? AND event_id=?`).bind(dep,area,new Date().toISOString(),volunteerId,eventId).run();return json({ok:true})}
async function listTaskLibrary(env:Env){const r=await env.DB.prepare(`SELECT * FROM task_library WHERE active=1 ORDER BY name COLLATE NOCASE`).all<any>();return json({ok:true,tasks:r.results.map(x=>({...x,eligibility:JSON.parse(x.eligibility_json||'[]')}))})}
async function saveTaskLibrary(req:Request,env:Env){const b=await body(req);if(!b)return bad('Invalid JSON');const p=parseTask(b);if('error'in p)return bad(p.error);const id=crypto.randomUUID(),now=new Date().toISOString();await env.DB.prepare(`INSERT INTO task_library(id,app,name,category,description,auto_schedule,eligibility_json,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,1,?,?)`).bind(id,clean(b.app)||null,p.value.name,clean(b.category)||null,p.value.description||null,p.value.autoSchedule,JSON.stringify(p.value.eligibility),now,now).run();return json({ok:true,id},201)}
async function addLibraryTaskToEvent(req:Request,env:Env,eventId:string,libraryId:string){const b=await body(req)||{};const x=await env.DB.prepare(`SELECT * FROM task_library WHERE id=? AND active=1`).bind(libraryId).first<any>();if(!x)return nf('Library task not found');const dep=clean(b.department_id)||(await env.DB.prepare(`SELECT id FROM departments WHERE event_id=? AND active=1 ORDER BY sort_order,id LIMIT 1`).bind(eventId).first<{id:string}>())?.id||'';if(!dep)return bad('Create a department first');const id=crypto.randomUUID(),now=new Date().toISOString(),elig=JSON.parse(x.eligibility_json||'["Anyone"]');await env.DB.batch([env.DB.prepare(`INSERT INTO tasks(id,event_id,name,category,description,active,auto_schedule,created_at,updated_at,department_id,library_task_id) VALUES(?,?,?,?,?,1,?,?,?,?,?)`).bind(id,eventId,x.name,x.category||'',x.description||null,x.auto_schedule,now,now,dep,libraryId),...elig.map((z:string)=>env.DB.prepare(`INSERT INTO task_eligibility(task_id,value) VALUES(?,?)`).bind(id,z))]);return json({ok:true,id},201)}
async function createSnapshot(req:Request,env:Env,eventId:string){if(!await getEvent(env,eventId))return nf('Event not found');const b=await body(req)||{},label=clean(b.label)||`Schedule ${new Date().toLocaleDateString('en-US')}`;const [e,v,t,s,a]=await Promise.all([getEvent(env,eventId),env.DB.prepare(`SELECT * FROM volunteers WHERE event_id=? ORDER BY last_name,first_name`).bind(eventId).all(),env.DB.prepare(`SELECT * FROM tasks WHERE event_id=? ORDER BY name`).bind(eventId).all(),env.DB.prepare(`SELECT * FROM slots WHERE event_id=? ORDER BY date,start_time`).bind(eventId).all(),env.DB.prepare(`SELECT * FROM assignments WHERE event_id=?`).bind(eventId).all()]);const id=crypto.randomUUID(),now=new Date().toISOString(),payload=JSON.stringify({event:e,volunteers:v.results,tasks:t.results,slots:s.results,assignments:a.results});await env.DB.prepare(`INSERT INTO schedule_snapshots(id,event_id,label,snapshot_json,created_at) VALUES(?,?,?,?,?)`).bind(id,eventId,label,payload,now).run();return json({ok:true,id,label,created_at:now},201)}
async function listSnapshots(env:Env,eventId:string){const r=await env.DB.prepare(`SELECT id,label,created_at,length(snapshot_json) bytes FROM schedule_snapshots WHERE event_id=? ORDER BY created_at DESC LIMIT 50`).bind(eventId).all();return json({ok:true,snapshots:r.results})}

function shell(app:AppCode,eventId?:string){
 const title=APP_NAMES[app], pageData=JSON.stringify({app,eventId:eventId||null}).replace(/</g,'\\u003c');
 return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>OurPortal — ${title}</title><link rel="stylesheet" href="/app.css"></head>
<body><header class="topbar"><div class="brand-wrap"><div class="brand">OurPortal</div><div class="product">Scheduler</div></div><nav class="app-switcher"><a href="/ca" ${app==='ca'?'aria-current="page"':''}>CA</a><a href="/rc" ${app==='rc'?'aria-current="page"':''}>RC</a><a href="/sc" ${app==='sc'?'aria-current="page"':''}>Other</a></nav></header>
<main id="app-root" class="page"></main><script>window.__OURPORTAL__=${pageData};</script><script src="/app.js" defer></script></body></html>`,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
}

export default {async fetch(request,env):Promise<Response>{
 const u=new URL(request.url),p=u.pathname.replace(/\/+$/,'')||'/';
 // Local Wrangler development remains usable without Cloudflare Access.
 // Production protected routes require a valid Access application JWT.
 if(u.hostname!=='localhost'&&u.hostname!=='127.0.0.1'&&needsAccess(p)&&!(await validateAccess(request))){
  return new Response('Cloudflare Access authentication required.',{status:403,headers:{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}});
 }
 try{
  const email=accessEmail(request);
  if(p==='/api/me'&&request.method==='GET')return json({ok:true,email,full_admin:await isFullAdmin(env,email)});
  if(p==='/')return Response.redirect(new URL('/ca',request.url).toString(),302);
  if(/^\/confirm\/[^/]+$/.test(p))return confirmationShell();
  if(/^\/entry\/[^/]+$/.test(p)||/^\/e\/[^/]+$/.test(p))return entryShell();
  const page=p.match(/^\/(ca|rc|sc)(?:\/events\/([^/]+))?$/); if(page)return shell(page[1] as AppCode,page[2]?decodeURIComponent(page[2]):undefined);
  if(p==='/api/events'&&request.method==='GET')return listEvents(request,env);
  if(p==='/api/events'&&request.method==='POST'){if(!await isFullAdmin(env,email))return json({ok:false,error:'Full Admin permission required.'},403);return createEvent(request,env);}
  const em=p.match(/^\/api\/events\/([^/]+)$/);
  if(em&&request.method==='GET'){const eid=decodeURIComponent(em[1]);if(!(await hasEventPermission(env,eid,email)))return json({ok:false,error:'You do not have permission to access this event.'},403);const e=await getEvent(env,eid);return e?json({ok:true,event:e}):nf('Event not found')}
  if(em&&request.method==='PATCH'){const eid=decodeURIComponent(em[1]);if(!(await isEventAdmin(env,eid,email)))return json({ok:false,error:'Event Admin permission required.'},403);return patchEvent(request,env,eid)}
  if(em&&request.method==='DELETE'){const eid=decodeURIComponent(em[1]);if(!(await isEventAdmin(env,eid,email)))return json({ok:false,error:'Event Admin permission required.'},403);return deleteEvent(request,env,eid)}
  const accessRoute=p.match(/^\/api\/events\/([^/]+)\/access$/);if(accessRoute&&request.method==='GET'){const eid=decodeURIComponent(accessRoute[1]);if(!(await hasEventPermission(env,eid,email)))return json({ok:false,error:'You do not have permission to access this event.'},403);return accessData(request,env,eid)}
  const mySch=p.match(/^\/api\/events\/([^/]+)\/my-schedule$/);if(mySch&&request.method==='GET')return mySchedule(request,env,decodeURIComponent(mySch[1]));
  const myAreaRoute=p.match(/^\/api\/events\/([^/]+)\/my-area$/);if(myAreaRoute&&request.method==='GET')return myArea(request,env,decodeURIComponent(myAreaRoute[1]));
  const eventRoute=p.match(/^\/api\/events\/([^/]+)\//);
  if(eventRoute){
   const eid=decodeURIComponent(eventRoute[1]);
   if(!(await hasEventPermission(env,eid,email)))return json({ok:false,error:'You do not have permission to access this event.'},403);
   // Lower roles are least-privilege by default. Department-scoped access is opened only
   // by the explicit checks below; unknown/new routes remain Event Admin only.
   if(!(await isEventAdmin(env,eid,email))){
    const u2=new URL(request.url),depQ=clean(u2.searchParams.get('department_id'));
    const readScoped=/\/(volunteers|tasks|slots|schedule|schedule-preflight)$/.test(p)&&request.method==='GET';
    const orgRead=/\/organization$/.test(p)&&request.method==='GET';
    if(readScoped){if(!depQ||!(await canAccessDepartment(env,eid,email,depQ)))return json({ok:false,error:'You do not have permission to access this department.'},403);}
    else if(orgRead){/* organization is required to render the permitted department workspace; UI filtering is applied client-side in this release */}
    else return json({ok:false,error:'This action requires Event Admin access.'},403);
   }
  }
  const perm=p.match(/^\/api\/events\/([^/]+)\/permissions$/);
  if(perm){if(!await isFullAdmin(env,email))return json({ok:false,error:'Full Admin permission required.'},403);if(request.method==='GET')return permissionData(env,decodeURIComponent(perm[1]));if(request.method==='POST')return addPermission(request,env,decodeURIComponent(perm[1]));}
  const permOne=p.match(/^\/api\/events\/([^/]+)\/permissions\/([^/]+)$/);if(permOne&&request.method==='DELETE'){if(!await isFullAdmin(env,email))return json({ok:false,error:'Full Admin permission required.'},403);return deletePermission(request,env,decodeURIComponent(permOne[1]),decodeURIComponent(permOne[2]));}
  const el=p.match(/^\/api\/events\/([^/]+)\/entry-link$/);
  if(el&&request.method==='PUT')return setEntryLink(request,env,decodeURIComponent(el[1]));
  const ep=p.match(/^\/api\/entry\/([^/]+)$/);
  if(ep&&request.method==='GET')return entryData(env,decodeURIComponent(ep[1]));
  if(ep&&request.method==='POST')return entryAdd(request,env,decodeURIComponent(ep[1]));
  const sep=p.match(/^\/api\/e\/([^/]+)$/);
  if(sep&&request.method==='GET')return shortEntryData(env,decodeURIComponent(sep[1]));
  if(sep&&request.method==='POST')return shortEntryAdd(request,env,decodeURIComponent(sep[1]));
  const vm=p.match(/^\/api\/events\/([^/]+)\/volunteers$/);
  if(vm&&request.method==='GET')return listVolunteers(request,env,decodeURIComponent(vm[1]));
  if(vm&&request.method==='POST')return createVolunteer(request,env,decodeURIComponent(vm[1]));
  if(vm&&request.method==='DELETE')return deleteVolunteers(request,env,decodeURIComponent(vm[1]));
  const vi=p.match(/^\/api\/events\/([^/]+)\/volunteers\/import$/); if(vi&&request.method==='POST')return importVolunteers(request,env,decodeURIComponent(vi[1]));
  const vp=p.match(/^\/api\/events\/([^/]+)\/volunteers\/([^/]+)$/); if(vp&&request.method==='PATCH')return patchVolunteer(request,env,decodeURIComponent(vp[1]),decodeURIComponent(vp[2]));
  const tm=p.match(/^\/api\/events\/([^/]+)\/tasks$/);
  if(tm&&request.method==='GET')return listTasks(request,env,decodeURIComponent(tm[1]));
  if(tm&&request.method==='POST')return createTask(request,env,decodeURIComponent(tm[1]));
  const tp=p.match(/^\/api\/events\/([^/]+)\/tasks\/([^/]+)$/);
  if(tp&&request.method==='PATCH')return patchTask(request,env,decodeURIComponent(tp[1]),decodeURIComponent(tp[2]));
  if(tp&&request.method==='DELETE')return deleteTask(env,decodeURIComponent(tp[1]),decodeURIComponent(tp[2]));
  const sm=p.match(/^\/api\/events\/([^/]+)\/slots$/);
  if(sm&&request.method==='GET')return listSlots(request,env,decodeURIComponent(sm[1]));
  if(sm&&request.method==='PUT')return saveSlots(request,env,decodeURIComponent(sm[1]));
  const sc=p.match(/^\/api\/events\/([^/]+)\/slots\/copy$/);
  if(sc&&request.method==='POST')return copySlots(request,env,decodeURIComponent(sc[1]));
  const am=p.match(/^\/api\/events\/([^/]+)\/availability$/);
  if(am&&request.method==='GET')return getAvailability(env,decodeURIComponent(am[1]));
  const avp=p.match(/^\/api\/events\/([^/]+)\/availability\/([^/]+)$/);
  if(avp&&request.method==='PUT')return saveVolunteerAvailability(request,env,decodeURIComponent(avp[1]),decodeURIComponent(avp[2]));
  const sch=p.match(/^\/api\/events\/([^/]+)\/schedule$/);
  if(sch&&request.method==='GET')return listSchedule(request,env,decodeURIComponent(sch[1]));
  if(sch&&request.method==='POST')return generateSchedule(request,env,decodeURIComponent(sch[1]));
  const sp=p.match(/^\/api\/events\/([^/]+)\/schedule-preflight$/);
  if(sp&&request.method==='GET')return schedulePreflight(request,env,decodeURIComponent(sp[1]));
  const sls=p.match(/^\/api\/events\/([^/]+)\/schedule-lock$/);
  if(sls&&request.method==='GET')return scheduleLockState(env,decodeURIComponent(sls[1]));
  if(sls&&request.method==='PUT'){const b=await body(request);return setEntireScheduleLock(env,decodeURIComponent(sls[1]),!!b?.locked)}
  const sal=p.match(/^\/api\/events\/([^/]+)\/schedule\/assignments\/([^/]+)\/lock$/);
  if(sal&&request.method==='PUT'){const b=await body(request);return setOneAssignmentLock(env,decodeURIComponent(sal[1]),decodeURIComponent(sal[2]),!!b?.locked)}
  const sac=p.match(/^\/api\/events\/([^/]+)\/schedule\/assignments\/([^/]+)\/volunteer$/);
  if(sac&&request.method==='PUT')return changeAssignmentVolunteer(request,env,decodeURIComponent(sac[1]),decodeURIComponent(sac[2]));
  const srm=p.match(/^\/api\/events\/([^/]+)\/schedule\/remove$/);
  if(srm&&request.method==='POST')return removeScheduleAssignments(request,env,decodeURIComponent(srm[1]));
  const sfo=p.match(/^\/api\/events\/([^/]+)\/schedule\/fill-open$/);
  if(sfo&&request.method==='POST')return fillOpenScheduleSlots(env,decodeURIComponent(sfo[1]));
  const srb=p.match(/^\/api\/events\/([^/]+)\/schedule\/rebalance-new$/);
  if(srb&&request.method==='POST')return rebalanceWithNewVolunteers(env,decodeURIComponent(srb[1]));
  const mail=p.match(/^\/api\/events\/([^/]+)\/schedule-email$/);if(mail&&request.method==='POST')return sendScheduleEmails(request,env,decodeURIComponent(mail[1]));
  const sms=p.match(/^\/api\/events\/([^/]+)\/schedule-sms$/);if(sms&&request.method==='POST')return prepareScheduleSms(request,env,decodeURIComponent(sms[1]));
  const mc=p.match(/^\/api\/events\/([^/]+)\/confirmations\/([^/]+)$/);if(mc&&request.method==='PUT')return manualConfirmation(request,env,decodeURIComponent(mc[1]),decodeURIComponent(mc[2]));
  const comm=p.match(/^\/api\/events\/([^/]+)\/communications$/);if(comm&&request.method==='GET')return communicationHistory(env,decodeURIComponent(comm[1]));
  const cd=p.match(/^\/api\/events\/([^/]+)\/confirmations$/);
  if(cd&&request.method==='GET')return confirmationDashboard(env,decodeURIComponent(cd[1]));
  const cgl=p.match(/^\/api\/events\/([^/]+)\/confirmation-links$/);
  if(cgl&&request.method==='POST')return generateConfirmationLinks(request,env,decodeURIComponent(cgl[1]));
  const people=p.match(/^\/api\/events\/([^/]+)\/people$/);if(people&&request.method==='GET')return listEventPeople(env,decodeURIComponent(people[1]));if(people&&request.method==='POST')return saveEventPerson(request,env,decodeURIComponent(people[1]));
  const person=p.match(/^\/api\/events\/([^/]+)\/people\/([^/]+)$/);if(person&&request.method==='PATCH')return saveEventPerson(request,env,decodeURIComponent(person[1]),decodeURIComponent(person[2]));if(person&&request.method==='DELETE')return deleteEventPerson(env,decodeURIComponent(person[1]),decodeURIComponent(person[2]));
  const org=p.match(/^\/api\/events\/([^/]+)\/organization$/);if(org&&request.method==='GET')return organizationData(env,decodeURIComponent(org[1]));
  const deps=p.match(/^\/api\/events\/([^/]+)\/departments$/);if(deps&&request.method==='POST')return saveDepartment(request,env,decodeURIComponent(deps[1]));
  const dep=p.match(/^\/api\/events\/([^/]+)\/departments\/([^/]+)$/);if(dep&&request.method==='PATCH')return saveDepartment(request,env,decodeURIComponent(dep[1]),decodeURIComponent(dep[2]));
  if(dep&&request.method==='DELETE')return deleteDepartment(request,env,decodeURIComponent(dep[1]),decodeURIComponent(dep[2]));
  const area=p.match(/^\/api\/events\/([^/]+)\/assistant-areas$/);if(area&&request.method==='POST')return saveArea(request,env,decodeURIComponent(area[1]));
  const node=p.match(/^\/api\/events\/([^/]+)\/org-nodes$/);if(node&&request.method==='POST')return saveOrgNode(request,env,decodeURIComponent(node[1]));
  const nodeOne=p.match(/^\/api\/events\/([^/]+)\/org-nodes\/([^/]+)$/);if(nodeOne&&request.method==='PATCH')return patchOrgNode(request,env,decodeURIComponent(nodeOne[1]),decodeURIComponent(nodeOne[2]));
  const mv=p.match(/^\/api\/events\/([^/]+)\/volunteers\/([^/]+)\/move$/);if(mv&&request.method==='PUT')return moveVolunteer(request,env,decodeURIComponent(mv[1]),decodeURIComponent(mv[2]));
  if(p==='/api/task-library'&&request.method==='GET')return listTaskLibrary(env);
  if(p==='/api/task-library'&&request.method==='POST')return saveTaskLibrary(request,env);
  const lte=p.match(/^\/api\/events\/([^/]+)\/tasks\/from-library\/([^/]+)$/);if(lte&&request.method==='POST')return addLibraryTaskToEvent(request,env,decodeURIComponent(lte[1]),decodeURIComponent(lte[2]));
  const snaps=p.match(/^\/api\/events\/([^/]+)\/snapshots$/);if(snaps&&request.method==='GET')return listSnapshots(env,decodeURIComponent(snaps[1]));if(snaps&&request.method==='POST')return createSnapshot(request,env,decodeURIComponent(snaps[1]));
  const cp=p.match(/^\/api\/confirm\/([^/]+)$/);
  if(cp&&request.method==='GET')return confirmationPageData(env,decodeURIComponent(cp[1]));
  if(cp&&request.method==='PUT')return saveConfirmationResponses(request,env,decodeURIComponent(cp[1]));
  if(p.startsWith('/api/'))return nf('API route not found'); return new Response('Not Found',{status:404});
 }catch(e){console.error(e);return json({ok:false,error:'Unexpected server error'},500)}
}} satisfies ExportedHandler<Env>;
