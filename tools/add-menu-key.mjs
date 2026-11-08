#!/usr/bin/env node
// Tambahkan kunci menu baru (mis. "soga") ke satu akun di users.json.
// Pakai:  node tools/add-menu-key.mjs <username> <menu> <file-kunci-base64>
// Password dibaca dari prompt (tidak disimpan). Hanya untuk akun tanpa OTP (o=0).
// Jalankan per akun yang perlu akses menu tersebut; kunci (soga.key) JANGAN di-commit.
import {readFileSync,writeFileSync} from 'fs';
import {createHash,webcrypto as c} from 'crypto';
import readline from 'readline';
const [user,menu,keyFile]=process.argv.slice(2);
if(!user||!menu||!keyFile){console.error('Usage: node tools/add-menu-key.mjs <username> <menu> <keyfile>');process.exit(1);}
const rl=readline.createInterface({input:process.stdin,output:process.stdout});
const pw=await new Promise(r=>rl.question('Password '+user+': ',r));rl.close();
const db=JSON.parse(readFileSync('users.json','utf8'));
const uid=createHash('sha256').update(user).digest('hex');
const rec=db.users[uid]; if(!rec){console.error('User tidak ditemukan');process.exit(1);}
if(rec.o){console.error('Akun memakai OTP; tidak didukung skrip ini');process.exit(1);}
const b64d=s=>new Uint8Array(Buffer.from(s,'base64')), b64e=u=>Buffer.from(u).toString('base64');
const base=await c.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
const bits=new Uint8Array(await c.subtle.deriveBits({name:'PBKDF2',salt:b64d(rec.s),iterations:rec.i,hash:'SHA-256'},base,256));
const kek=await c.subtle.importKey('raw',bits,'AES-GCM',false,['encrypt','decrypt']);
try{await c.subtle.decrypt({name:'AES-GCM',iv:b64d(rec.k[Object.keys(rec.k)[0]].iv)},kek,b64d(rec.k[Object.keys(rec.k)[0]].ct));}catch{console.error('Password salah');process.exit(1);}
const iv=c.getRandomValues(new Uint8Array(12));
const ct=new Uint8Array(await c.subtle.encrypt({name:'AES-GCM',iv},kek,b64d(readFileSync(keyFile,'utf8').trim())));
rec.k[menu]={iv:b64e(iv),ct:b64e(ct)};
db.build=createHash('sha256').update(String(Date.now())).digest('hex').slice(0,12);
writeFileSync('users.json',JSON.stringify(db));
console.log('OK: menu "'+menu+'" ditambahkan untuk '+user+'; build='+db.build);
