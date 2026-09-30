import express from 'express';
import session from 'express-session';
import pg from 'pg';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const RP_ID = process.env.RP_ID || new URL(BASE_URL).hostname;
const RP_NAME = process.env.RP_NAME || 'ITBA P4 Quiz';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. For local testing, provide a PostgreSQL connection string.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: BASE_URL.startsWith('https://'), maxAge: 1000 * 60 * 60 * 12 }
}));

const schema = `
CREATE TABLE IF NOT EXISTS access_requests (
 id SERIAL PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending',
 setup_code_hash TEXT,
 created_at TIMESTAMPTZ NOT NULL,
 approved_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS users (
 id SERIAL PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'approved',
 created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
 id SERIAL PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 credential_id TEXT NOT NULL UNIQUE,
 public_key BYTEA NOT NULL,
 counter BIGINT NOT NULL DEFAULT 0,
 transports TEXT,
 created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_email ON access_requests(email);
`;

const questions = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/questions.json'), 'utf8'));
const TOPICS = [[1,50,'ITBA fundamentals, modules and core functions'],[51,82,'Assessment, scrutiny and HRMS'],[83,100,'Project Insight, AIS, security and digital forensics'],[101,125,'ITBA workflow, assessment and administration'],[126,140,'HRMS, e-Nivaran, PAN and TDS'],[141,160,'Information security and ITBA controls'],[161,175,'Recovery, audit, appeals, OGE and penalty'],[176,200,'Project Insight, AIS, information security and digital forensics'],[201,218,'ITBA, assessment, appeals, HRMS and Insight'],[219,268,'P4 source-order topic section 219–268'],[269,318,'P4 source-order topic section 269–318'],[319,368,'P4 source-order topic section 319–368'],[369,400,'P4 source-order topic section 369–400']];

function now(){return new Date().toISOString()}
function hash(s){return crypto.createHash('sha256').update(s).digest('hex')}
function randomCode(){return crypto.randomBytes(5).toString('hex').toUpperCase()}
function normalizeEmail(e){return String(e||'').trim().toLowerCase()}
function requireUser(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Authentication required'});next()}
function requireAdmin(req,res,next){if(!req.session.admin)return res.status(401).json({error:'Admin authentication required'});next()}
async function q(text, params=[]){return pool.query(text,params)}

function shuffle(a){a=[...a];for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]]}return a}
function balanced(count){
  if(![10,100].includes(count)) return shuffle(questions).slice(0,count);
  const pools=TOPICS.map(([s,e])=>questions.filter(q=>q.id>=s&&q.id<=e));
  const base=Math.floor(count/pools.length), rem=count%pools.length;
  let out=[]; pools.forEach((p,i)=>out.push(...shuffle(p).slice(0,Math.min(p.length,base+(i<rem?1:0)))));
  if(out.length<count){const ids=new Set(out.map(q=>q.id));out.push(...shuffle(questions.filter(q=>!ids.has(q.id))).slice(0,count-out.length));}
  return shuffle(out).slice(0,count);
}

app.get('/api/health',async(req,res)=>{
  try { await q('SELECT 1'); res.json({ok:true}); }
  catch(e){res.status(503).json({ok:false});}
});
app.get('/api/me',(req,res)=>res.json({authenticated:!!req.session.userId,user:req.session.userId?{id:req.session.userId,name:req.session.name,email:req.session.email}:null}));

app.post('/api/request-access',async(req,res)=>{
  try {
    const name=String(req.body.name||'').trim(); const email=normalizeEmail(req.body.email);
    if(name.length<2||!email.includes('@')) return res.status(400).json({error:'Enter a valid name and email.'});
    const existing=(await q('SELECT * FROM access_requests WHERE email=$1',[email])).rows[0];
    if(existing){
      if(existing.status==='approved') return res.json({ok:true,status:'approved',message:'Your access is approved. Ask the administrator for your one-time setup code.'});
      return res.json({ok:true,status:existing.status,message:'Your request is already recorded.'});
    }
    await q('INSERT INTO access_requests(name,email,status,created_at) VALUES($1,$2,$3,$4)',[name,email,'pending',now()]);
    res.json({ok:true,status:'pending',message:'Request submitted. The administrator must approve it.'});
  } catch(e){res.status(500).json({error:'Could not submit access request.'});}
});

app.post('/api/admin/login',(req,res)=>{if(String(req.body.password||'')!==ADMIN_PASSWORD)return res.status(403).json({error:'Invalid admin password'});req.session.admin=true;res.json({ok:true})});
app.post('/api/admin/logout',(req,res)=>{req.session.admin=false;res.json({ok:true})});
app.get('/api/admin/requests',requireAdmin,async(req,res)=>{
  const requests=(await q('SELECT id,name,email,status,created_at,approved_at FROM access_requests ORDER BY id DESC')).rows;
  const users=(await q('SELECT id,name,email,status,created_at FROM users ORDER BY id DESC')).rows;
  res.json({requests,users});
});
app.post('/api/admin/approve/:id',requireAdmin,async(req,res)=>{
  const r=(await q('SELECT * FROM access_requests WHERE id=$1',[Number(req.params.id)])).rows[0];
  if(!r)return res.status(404).json({error:'Request not found'});
  const code=randomCode();
  await q(`INSERT INTO users(name,email,status,created_at) VALUES($1,$2,$3,$4)
    ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,status='approved'`,[r.name,r.email,'approved',now()]);
  await q('UPDATE access_requests SET status=$1,setup_code_hash=$2,approved_at=$3 WHERE id=$4',['approved',hash(code),now(),r.id]);
  res.json({ok:true,email:r.email,setupCode:code,message:'Give this one-time setup code to the approved user through a private channel.'});
});
app.post('/api/admin/revoke/:id',requireAdmin,async(req,res)=>{
  const u=(await q('SELECT * FROM users WHERE id=$1',[Number(req.params.id)])).rows[0]; if(!u)return res.status(404).json({error:'User not found'});
  await q('UPDATE users SET status=$1 WHERE id=$2',['revoked',u.id]);
  await q('DELETE FROM credentials WHERE user_id=$1',[u.id]);
  res.json({ok:true});
});
app.post('/api/admin/reset-device/:id',requireAdmin,async(req,res)=>{
  const u=(await q('SELECT * FROM users WHERE id=$1',[Number(req.params.id)])).rows[0]; if(!u)return res.status(404).json({error:'User not found'});
  const code=randomCode(); await q('DELETE FROM credentials WHERE user_id=$1',[u.id]);
  await q('UPDATE access_requests SET setup_code_hash=$1,status=$2,approved_at=$3 WHERE email=$4',[hash(code),'approved',now(),u.email]);
  res.json({ok:true,email:u.email,setupCode:code});
});

app.post('/api/auth/register/options',async(req,res)=>{
  try {
    const email=normalizeEmail(req.body.email), code=String(req.body.setupCode||'').trim().toUpperCase();
    const r=(await q('SELECT * FROM access_requests WHERE email=$1',[email])).rows[0];
    const u=(await q('SELECT * FROM users WHERE email=$1',[email])).rows[0];
    if(!r||!u||u.status!=='approved'||!r.setup_code_hash||hash(code)!==r.setup_code_hash)return res.status(403).json({error:'Invalid email or setup code.'});
    const existing=(await q('SELECT credential_id FROM credentials WHERE user_id=$1',[u.id])).rows.map(x=>({id:x.credential_id}));
    const options=await generateRegistrationOptions({rpName:RP_NAME,rpID:RP_ID,userName:email,userDisplayName:u.name,attestationType:'none',excludeCredentials:existing,authenticatorSelection:{residentKey:'required',userVerification:'required'}});
    req.session.regUserId=u.id; req.session.regEmail=email; req.session.regChallenge=options.challenge;
    res.json(options);
  } catch(e){res.status(400).json({error:e.message||'Could not start registration.'});}
});
app.post('/api/auth/register/verify',async(req,res)=>{
  try{
    if(!req.session.regUserId||!req.session.regChallenge)return res.status(400).json({error:'Registration session expired. Start again.'});
    const verification=await verifyRegistrationResponse({response:req.body.response,expectedChallenge:req.session.regChallenge,expectedOrigin:BASE_URL,expectedRPID:RP_ID,requireUserVerification:true});
    if(!verification.verified||!verification.registrationInfo)return res.status(400).json({error:'Passkey registration was not verified.'});
    const {credential}=verification.registrationInfo;
    await q('INSERT INTO credentials(user_id,credential_id,public_key,counter,transports,created_at) VALUES($1,$2,$3,$4,$5,$6)',[req.session.regUserId,credential.id,Buffer.from(credential.publicKey),credential.counter,JSON.stringify(credential.transports||[]),now()]);
    await q('UPDATE access_requests SET setup_code_hash=NULL WHERE email=$1',[req.session.regEmail]);
    req.session.userId=req.session.regUserId; const u=(await q('SELECT * FROM users WHERE id=$1',[req.session.userId])).rows[0]; req.session.name=u.name;req.session.email=u.email;
    delete req.session.regUserId;delete req.session.regEmail;delete req.session.regChallenge;
    res.json({verified:true});
  }catch(e){res.status(400).json({error:e.message||'Verification failed'});}
});

app.post('/api/auth/login/options',async(req,res)=>{
  try {
    const email=normalizeEmail(req.body.email); const u=(await q('SELECT * FROM users WHERE email=$1',[email])).rows[0];
    if(!u||u.status!=='approved')return res.status(403).json({error:'No approved account found.'});
    const creds=(await q('SELECT credential_id,transports FROM credentials WHERE user_id=$1',[u.id])).rows;
    if(!creds.length)return res.status(400).json({error:'No registered device. Use your setup code to register this phone first.'});
    const options=await generateAuthenticationOptions({rpID:RP_ID,allowCredentials:creds.map(c=>({id:c.credential_id,transports:JSON.parse(c.transports||'[]')})),userVerification:'required'});
    req.session.authUserId=u.id;req.session.authChallenge=options.challenge;res.json(options);
  } catch(e){res.status(400).json({error:e.message||'Could not start login.'});}
});
app.post('/api/auth/login/verify',async(req,res)=>{
  try{
    if(!req.session.authUserId||!req.session.authChallenge)return res.status(400).json({error:'Login session expired.'});
    const u=(await q('SELECT * FROM users WHERE id=$1',[req.session.authUserId])).rows[0]; if(!u||u.status!=='approved')return res.status(403).json({error:'Account is not approved.'});
    const c=(await q('SELECT * FROM credentials WHERE credential_id=$1 AND user_id=$2',[req.body.response?.id,u.id])).rows[0]; if(!c)return res.status(403).json({error:'This device is not registered for this account.'});
    const verification=await verifyAuthenticationResponse({response:req.body.response,expectedChallenge:req.session.authChallenge,expectedOrigin:BASE_URL,expectedRPID:RP_ID,credential:{id:c.credential_id,publicKey:new Uint8Array(c.public_key),counter:Number(c.counter),transports:JSON.parse(c.transports||'[]')},requireUserVerification:true});
    if(!verification.verified)return res.status(403).json({error:'Passkey verification failed.'});
    await q('UPDATE credentials SET counter=$1 WHERE id=$2',[verification.authenticationInfo.newCounter,c.id]);
    req.session.userId=u.id;req.session.name=u.name;req.session.email=u.email;delete req.session.authUserId;delete req.session.authChallenge;res.json({verified:true});
  }catch(e){res.status(400).json({error:e.message||'Verification failed'});}
});
app.post('/api/logout',(req,res)=>{req.session.destroy(()=>res.json({ok:true}))});
app.get('/api/quiz',requireUser,(req,res)=>{const count=Math.min(Math.max(Number(req.query.count||10),1),400);res.json({questions:balanced(count),negativeMarking:{correct:1,wrong:-0.125,unanswered:0}})});

app.use(express.static(path.join(__dirname,'public')));
app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

(async()=>{
  try { await pool.query(schema); console.log('Database ready'); app.listen(PORT,()=>console.log(`P4 mobile quiz running at ${BASE_URL}`)); }
  catch(e){ console.error('Database initialization failed:',e); process.exit(1); }
})();
