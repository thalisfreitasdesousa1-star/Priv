const PRIV_ADMIN_EMAIL="thalisfreitasdesousa1@gmail.com";
const PRIV_ENCODER=new TextEncoder();
const PRIV_HEX=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,"0")).join("");
const PRIV_FROM_HEX=s=>Uint8Array.from(String(s).match(/.{2}/g)||[],x=>parseInt(x,16));
async function privSha(value){return PRIV_HEX(await crypto.subtle.digest("SHA-256",PRIV_ENCODER.encode(value)))}
function privEqual(a,b){a=String(a||"");b=String(b||"");let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0}
async function privPasswordHash(password,salt){const key=await crypto.subtle.importKey("raw",PRIV_ENCODER.encode(password),"PBKDF2",false,["deriveBits"]);return PRIV_HEX(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:PRIV_FROM_HEX(salt),iterations:250000},key,256))}
function privJson(data,status=200,headers={}){return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...headers}})}
function privCookie(request){const raw=request.headers.get("cookie")||"";const match=raw.match(/(?:^|;\s*)priv_admin=([a-f0-9]{64})(?:;|$)/);return match?.[1]||""}
async function privSession(request,env){const token=privCookie(request);if(!token)return null;const hash=await privSha(token);const now=Math.floor(Date.now()/1000);return await env.PRIV_DB.prepare("SELECT email FROM admin_sessions WHERE token_hash=? AND expires_at>?").bind(hash,now).first()}
async function privIssueSession(email,env){const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);const token=PRIV_HEX(bytes);const hash=await privSha(token);const expires=Math.floor(Date.now()/1000)+604800;await env.PRIV_DB.prepare("DELETE FROM admin_sessions WHERE expires_at<=?").bind(Math.floor(Date.now()/1000)).run();await env.PRIV_DB.prepare("INSERT INTO admin_sessions(token_hash,email,expires_at) VALUES(?,?,?)").bind(hash,email,expires).run();return{"set-cookie":"priv_admin="+token+"; Path=/api/admin; Max-Age=604800; HttpOnly; Secure; SameSite=Strict"}}
async function routePrivAdmin(request,env,path){
if(!path.startsWith("/api/admin/"))return null;
const url=new URL(request.url),origin=request.headers.get("origin");
if(["POST","PUT","DELETE"].includes(request.method)&&origin&&origin!==url.origin)return privJson({error:"Origem não autorizada."},403);
try{
if(path==="/api/admin/setup-status"&&request.method==="GET"){const admins=await env.PRIV_DB.prepare("SELECT COUNT(*) AS total FROM admins").first();const token=await env.PRIV_DB.prepare("SELECT COUNT(*) AS total FROM setup_tokens WHERE expires_at>?").bind(Math.floor(Date.now()/1000)).first();return privJson({available:Number(admins?.total||0)===0&&Number(token?.total||0)>0})}\nif(path==="/api/admin/setup"){
if(request.method!=="POST")return privJson({error:"Método não permitido."},405);
const count=await env.PRIV_DB.prepare("SELECT COUNT(*) AS total FROM admins").first();
if(Number(count?.total||0)>0)return privJson({error:"A conta inicial já foi ativada."},409);
const body=await request.json();const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||""),setupToken=String(body.setupToken||"");
if(email!==PRIV_ADMIN_EMAIL||password.length<12||password.length>128||!env.PRIV_SETUP_TOKEN||!setupToken)return privJson({error:"Dados inválidos. A senha deve ter 12 a 128 caracteres."},400);
const tokenHash=await privSha(setupToken),secretHash=await privSha(env.PRIV_SETUP_TOKEN),valid=await env.PRIV_DB.prepare("SELECT token_hash FROM setup_tokens WHERE token_hash=? AND expires_at>?").bind(tokenHash,Math.floor(Date.now()/1000)).first();
if(!valid||!privEqual(tokenHash,secretHash))return privJson({error:"O link de ativação expirou ou já foi usado."},403);
const saltBytes=new Uint8Array(16);crypto.getRandomValues(saltBytes);const salt=PRIV_HEX(saltBytes),hash=await privPasswordHash(password,salt);
await env.PRIV_DB.prepare("INSERT INTO admins(email,salt,password_hash,created_at) VALUES(?,?,?,?)").bind(email,salt,hash,Math.floor(Date.now()/1000)).run();
await env.PRIV_DB.prepare("DELETE FROM setup_tokens").run();const cookie=await privIssueSession(email,env);
return privJson({ok:true,email},201,cookie)
}
if(path==="/api/admin/login"){
if(request.method!=="POST")return privJson({error:"Método não permitido."},405);
const body=await request.json();const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
const admin=email===PRIV_ADMIN_EMAIL?await env.PRIV_DB.prepare("SELECT email,salt,password_hash FROM admins WHERE email=?").bind(email).first():null;
if(!admin||password.length>128)return privJson({error:"E-mail ou senha incorretos."},401);
const candidate=await privPasswordHash(password,admin.salt);if(!privEqual(candidate,admin.password_hash))return privJson({error:"E-mail ou senha incorretos."},401);
const cookie=await privIssueSession(email,env);return privJson({ok:true,email},200,cookie)
}
if(path==="/api/admin/logout"){
if(request.method!=="POST")return privJson({error:"Método não permitido."},405);
const token=privCookie(request);if(token)await env.PRIV_DB.prepare("DELETE FROM admin_sessions WHERE token_hash=?").bind(await privSha(token)).run();
return privJson({ok:true},200,{"set-cookie":"priv_admin=; Path=/api/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict"})
}
const session=await privSession(request,env);if(!session||session.email!==PRIV_ADMIN_EMAIL)return privJson({error:"Entre novamente para continuar."},401);
if(path==="/api/admin/session"&&request.method==="GET")return privJson({ok:true,email:session.email});
if(path==="/api/admin/content"&&request.method==="GET"){const row=await env.PRIV_DB.prepare("SELECT content FROM site_content WHERE id=1").first();return privJson(row?JSON.parse(row.content):{site:{},profiles:[],spaces:[]})}
if(path==="/api/admin/content"&&request.method==="PUT"){
const raw=await request.text();if(raw.length>100000)return privJson({error:"O conteúdo excede o limite permitido."},413);
const data=JSON.parse(raw);if(!data||!data.site||!Array.isArray(data.profiles)||data.profiles.length>30)return privJson({error:"Formato de conteúdo inválido."},400);
for(const p of data.profiles){if(!p||typeof p!=="object")return privJson({error:"Perfil inválido."},400);p.name=String(p.name||"").trim();p.bio=String(p.bio||"").trim();p.photos=Array.isArray(p.photos)?p.photos.slice(0,12):[];const adult=p.adultVerified===true||Number(p.age)>=18;if(p.published===true&&(!p.name||p.consent!==true||!adult||p.photos.length===0))return privJson({error:"Para publicar: informe nome, foto, autorização e confirmação de maioridade."},400);if(p.photos.some(u=>typeof u!=="string"||!(/^https:\/\//i.test(u)||/^\/assets\/[a-z0-9._/-]+$/i.test(u))))return privJson({error:"As fotos devem usar HTTPS ou o caminho /assets/."},400)}
const serialized=JSON.stringify(data);await env.PRIV_DB.prepare("UPDATE site_content SET content=?,updated_at=? WHERE id=1").bind(serialized,Math.floor(Date.now()/1000)).run();return privJson({ok:true,updatedAt:Math.floor(Date.now()/1000)})
}
return privJson({error:"Recurso não encontrado."},404)
}catch(error){return privJson({error:"Não foi possível processar a solicitação."},500)}
}