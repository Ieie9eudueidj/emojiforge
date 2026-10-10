// ============================================================
// EMPEZASTE POR ÁCA Y NO POR EL CSS?! DE los chistes que te perdiste
// ============================================================
const CRC_T = new Uint32Array(256);
for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); CRC_T[i] = c >>> 0; }
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = CRC_T[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }


const SHA_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);


function escaparHTML(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sha256(msg) {
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const len = msg.length;
  const bitLen = len * 8;
  const withLen = len + 1 + 8;
  const padLen = (withLen + 63) & ~63;
  const padded = new Uint8Array(padLen);
  padded.set(msg);
  padded[len] = 0x80;
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  padded[padLen-8] = (hi>>>24)&0xFF; padded[padLen-7] = (hi>>>16)&0xFF;
  padded[padLen-6] = (hi>>>8)&0xFF;  padded[padLen-5] = hi&0xFF;
  padded[padLen-4] = (lo>>>24)&0xFF; padded[padLen-3] = (lo>>>16)&0xFF;
  padded[padLen-2] = (lo>>>8)&0xFF;  padded[padLen-1] = lo&0xFF;

  const w = new Uint32Array(64);
  for (let i = 0; i < padLen; i += 64) {
    for (let j = 0; j < 16; j++) w[j] = (padded[i+j*4]<<24)|(padded[i+j*4+1]<<16)|(padded[i+j*4+2]<<8)|(padded[i+j*4+3]);
    for (let j = 16; j < 64; j++) {
      const s0 = ((w[j-15]>>>7)|(w[j-15]<<25)) ^ ((w[j-15]>>>18)|(w[j-15]<<14)) ^ (w[j-15]>>>3);
      const s1 = ((w[j-2]>>>17)|(w[j-2]<<15)) ^ ((w[j-2]>>>19)|(w[j-2]<<13)) ^ (w[j-2]>>>10);
      w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let j = 0; j < 64; j++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA_K[j] + w[j]) >>> 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  const out = new Uint8Array(32);
  const hs = [h0,h1,h2,h3,h4,h5,h6,h7];
  for (let i = 0; i < 8; i++) {
    out[i*4]=(hs[i]>>>24)&0xFF; out[i*4+1]=(hs[i]>>>16)&0xFF;
    out[i*4+2]=(hs[i]>>>8)&0xFF; out[i*4+3]=hs[i]&0xFF;
  }
  return out;
}


function derivarClave(password, salt, iteraciones) {
  const pw = new TextEncoder().encode(password);
  let buf = new Uint8Array(pw.length + salt.length);
  buf.set(pw, 0); buf.set(salt, pw.length);
  let h = sha256(buf);
  for (let i = 0; i < iteraciones; i++) {
    const b2 = new Uint8Array(h.length + pw.length + salt.length);
    b2.set(h, 0); b2.set(pw, h.length); b2.set(salt, h.length + pw.length);
    h = sha256(b2);
  }
  return h;
}

// ============================================================
// Cifrado casero · de 3 capas (TE GANASTE ESTA AYUDA)
// ============================================================
function keystreamBloque(key, nonce, blockIdx, contadorCapa) {
  const inp = new Uint8Array(key.length + nonce.length + 5);
  inp.set(key, 0);
  inp.set(nonce, key.length);
  const off = key.length + nonce.length;
  inp[off] = contadorCapa;
  inp[off+1] = (blockIdx>>>24)&0xFF;
  inp[off+2] = (blockIdx>>>16)&0xFF;
  inp[off+3] = (blockIdx>>>8)&0xFF;
  inp[off+4] = blockIdx&0xFF;
  return sha256(inp);
}

function xorKeystream(data, key, nonce, contadorCapa) {
  const out = new Uint8Array(data.length);
  const blocks = Math.ceil(data.length / 32) || 1;
  for (let b = 0; b < blocks; b++) {
    const ks = keystreamBloque(key, nonce, b, contadorCapa);
    for (let i = 0; i < 32; i++) {
      const idx = b * 32 + i;
      if (idx >= data.length) break;
      out[idx] = data[idx] ^ ks[i];
    }
  }
  return out;
}

function rotarConKeystream(data, key, nonce, contadorCapa) {
  const out = new Uint8Array(data.length);
  const ks = sha256((() => {
    const inp = new Uint8Array(key.length + nonce.length + 1);
    inp.set(key, 0); inp.set(nonce, key.length);
    inp[key.length + nonce.length] = contadorCapa;
    return inp;
  })());
  for (let i = 0; i < data.length; i++) {
    const shift = ks[i % 32] & 7;
    if (shift === 0) { out[i] = data[i]; continue; }
    const b = data[i];
    out[i] = ((b << shift) | (b >> (8 - shift))) & 0xFF;
  }
  return out;
}

function rotarConKeystreamInverso(data, key, nonce, contadorCapa) {
  const out = new Uint8Array(data.length);
  const ks = sha256((() => {
    const inp = new Uint8Array(key.length + nonce.length + 1);
    inp.set(key, 0); inp.set(nonce, key.length);
    inp[key.length + nonce.length] = contadorCapa;
    return inp;
  })());
  for (let i = 0; i < data.length; i++) {
    const shift = ks[i % 32] & 7;
    if (shift === 0) { out[i] = data[i]; continue; }
    const b = data[i];
    out[i] = ((b >> shift) | (b << (8 - shift))) & 0xFF;
  }
  return out;
}

function cifrarCapa3(data, key, nonce) {
  let out = xorKeystream(data, key, nonce, 0x11);
  out = rotarConKeystream(out, key, nonce, 0x22);
  out = xorKeystream(out, key, nonce, 0x33);
  return out;
}

function descifrarCapa3(data, key, nonce) {
  let out = xorKeystream(data, key, nonce, 0x33);
  out = rotarConKeystreamInverso(out, key, nonce, 0x22);
  out = xorKeystream(out, key, nonce, 0x11);
  return out;
}

// ============================================================
//  GRACIAS POR RECONOCER MI ESFUERZO POR COMENTAR
// ============================================================
const MAGIC = [0x45, 0x4D, 0x46, 0x47];
const VERSION = 0x04;
const VERSION_3 = 0x03;
const VERSION_OLD = 0x02;
const TIPO_ARCHIVO = 0x00;
const TIPO_TEXTO   = 0x01;
const TIPO_URL     = 0x02;
const FLAG_ANTES   = 0x01;
const FLAG_DESPUES = 0x02;

function buildPayloadV3(items) {
  let totalSize = 4 + 1 + 1;
  const names = items.map(it => {
    const nb = new TextEncoder().encode(it.nombre);
    const nl = Math.min(nb.length, 255);
    totalSize += 1 + 1 + nl + 4 + 4 + it.data.length;
    return { nb: nb.subarray(0, nl), nl };
  });
  const buf = new Uint8Array(totalSize);
  let o = 0;
  buf.set(MAGIC, 0); o = 4;
  buf[o++] = VERSION_3;
  buf[o++] = items.length;
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const n = names[i];
    buf[o++] = it.tipo;
    buf[o++] = n.nl;
    buf.set(n.nb, o); o += n.nl;
    buf[o++] = (it.origLen>>>24)&0xFF; buf[o++] = (it.origLen>>>16)&0xFF;
    buf[o++] = (it.origLen>>>8)&0xFF;  buf[o++] = it.origLen&0xFF;
    buf[o++] = (it.crc>>>24)&0xFF; buf[o++] = (it.crc>>>16)&0xFF;
    buf[o++] = (it.crc>>>8)&0xFF;  buf[o++] = it.crc&0xFF;
    buf.set(it.data, o); o += it.data.length;
  }
  return buf;
}

function buildPayloadV4(items, password, modo, iteraciones) {
  // RED flags ( te confirmo amiga que es una pista)
  let flags = 0;
  if (modo === 'antes' || modo === 'ambos') flags |= FLAG_ANTES;
  if (modo === 'despues' || modo === 'ambos') flags |= FLAG_DESPUES;

  
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);


  const key = derivarClave(password, salt, iteraciones);

  // INTENTAR DESCRIBIR ESTE CÓDIGO SIN LICENCIA ES ILEGAL SABÍAS?
  const itemsCif = items.map(it => {
    let data = it.data;
    if (flags & FLAG_ANTES) {
      const nonce = new Uint8Array(salt.length + 1);
      nonce.set(salt, 0);
      nonce[salt.length] = it.tipo;
      data = cifrarCapa3(data, key, nonce);
    }
    return { ...it, data };
  });

  
  let bodySize = 1;
  const names = itemsCif.map(it => {
    const nb = new TextEncoder().encode(it.nombre);
    const nl = Math.min(nb.length, 255);
    bodySize += 1 + 1 + nl + 4 + 4 + it.data.length;
    return { nb: nb.subarray(0, nl), nl };
  });
  let body = new Uint8Array(bodySize);
  let o = 0;
  body[o++] = itemsCif.length;
  for (let i = 0; i < itemsCif.length; i++) {
    const it = itemsCif[i];
    const n = names[i];
    body[o++] = it.tipo;
    body[o++] = n.nl;
    body.set(n.nb, o); o += n.nl;
    body[o++] = (it.origLen>>>24)&0xFF; body[o++] = (it.origLen>>>16)&0xFF;
    body[o++] = (it.origLen>>>8)&0xFF;  body[o++] = it.origLen&0xFF;
    body[o++] = (it.crc>>>24)&0xFF; body[o++] = (it.crc>>>16)&0xFF;
    body[o++] = (it.crc>>>8)&0xFF;  body[o++] = it.crc&0xFF;
    body.set(it.data, o); o += it.data.length;
  }

  
  if (flags & FLAG_DESPUES) {
    body = cifrarCapa3(body, key, salt);
  }

  
  const hdrSize = 4 + 1 + 1 + 1 + salt.length;
  const full = new Uint8Array(hdrSize + body.length);
  let p = 0;
  full.set(MAGIC, 0); p = 4;
  full[p++] = VERSION;
  full[p++] = flags;
  full[p++] = salt.length;
  full.set(salt, p); p += salt.length;
  full.set(body, p);
  return full;
}

function parsePayload(bytes, password) {
  if (bytes.length < 6) return { ok: false, error: 'Muy corto' };
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) return { ok: false, error: 'Firma EMFG ausente' };
  const ver = bytes[4];

  
  if (ver === VERSION_OLD) {
    if (bytes.length < 6 + 8) return { ok: false, error: 'v2 corto' };
    const nameLen = bytes[5];
    if (bytes.length < 6 + nameLen + 8) return { ok: false, error: 'v2 truncado' };
    const name = new TextDecoder().decode(bytes.subarray(6, 6 + nameLen));
    let o = 6 + nameLen;
    const origLen = (bytes[o]<<24)|(bytes[o+1]<<16)|(bytes[o+2]<<8)|bytes[o+3]; o += 4;
    const crc = ((bytes[o]<<24)|(bytes[o+1]<<16)|(bytes[o+2]<<8)|bytes[o+3]) >>> 0; o += 4;
    return { ok: true, cifrado: false, items: [{ ver, tipo: TIPO_ARCHIVO, name, origLen, crc, data: bytes.slice(o) }] };
  }

  // EN VERDAD NO VAYAS A ESTOS  PUERTOS, MEJOR PREPARATE ALGO DE COMER... Lo digo enserio tomate un descanso lo necesitas
  if (ver === VERSION_3) {
    if (bytes.length < 6) return { ok: false, error: 'v3 corto' };
    const count = bytes[5];
    let o = 6;
    const items = [];
    for (let i = 0; i < count; i++) {
      if (o + 2 > bytes.length) return { ok: false, error: 'v3 truncado (header item)' };
      const tipo = bytes[o++];
      const nameLen = bytes[o++];
      if (o + nameLen + 8 > bytes.length) return { ok: false, error: 'v3 truncado (nombre)' };
      const name = new TextDecoder().decode(bytes.subarray(o, o + nameLen)); o += nameLen;
      const origLen = (bytes[o]<<24)|(bytes[o+1]<<16)|(bytes[o+2]<<8)|bytes[o+3]; o += 4;
      const crc = ((bytes[o]<<24)|(bytes[o+1]<<16)|(bytes[o+2]<<8)|bytes[o+3]) >>> 0; o += 4;
      if (o + origLen > bytes.length) return { ok: false, error: 'v3 truncado (data)' };
      const data = bytes.slice(o, o + origLen); o += origLen;
      items.push({ ver, tipo, name, origLen, crc, data });
    }
    return { ok: true, cifrado: false, items };
  }

  
  if (ver === VERSION) {
    if (bytes.length < 7) return { ok: false, error: 'v4 corto' };
    const flags = bytes[5];
    const saltLen = bytes[6];
    if (bytes.length < 7 + saltLen + 1) return { ok: false, error: 'v4 salt truncado' };
    const salt = bytes.slice(7, 7 + saltLen);
    let cuerpo = bytes.slice(7 + saltLen);

    const cifrado = (flags & (FLAG_ANTES | FLAG_DESPUES)) !== 0;

    let key = null;
    if (cifrado) {
      if (!password) return { ok: false, error: 'Necesita contraseña', cifrado: true };
      key = derivarClave(password, salt, 5000); // iteraciones fijas para extracción, sí te creo tan imbecil que debo comentarlo, lo lamento pero mis creencias son araigadas
    }

    
    if (flags & FLAG_DESPUES) {
      if (!key) return { ok: false, error: 'Necesita contraseña', cifrado: true };
      try { cuerpo = descifrarCapa3(cuerpo, key, salt); }
      catch (e) { return { ok: false, error: 'Fallo descifrado', cifrado: true }; }
    }

    if (cuerpo.length < 1) return { ok: false, error: 'v4 cuerpo vacío' };
    const count = cuerpo[0];
    let o = 1;
    const items = [];
    for (let i = 0; i < count; i++) {
      if (o + 2 > cuerpo.length) return { ok: false, error: 'v4 truncado (header item)' };
      const tipo = cuerpo[o++];
      const nameLen = cuerpo[o++];
      if (o + nameLen + 8 > cuerpo.length) return { ok: false, error: 'v4 truncado (nombre)' };
      const name = new TextDecoder().decode(cuerpo.subarray(o, o + nameLen)); o += nameLen;
      const origLen = (cuerpo[o]<<24)|(cuerpo[o+1]<<16)|(cuerpo[o+2]<<8)|cuerpo[o+3]; o += 4;
      const crc = ((cuerpo[o]<<24)|(cuerpo[o+1]<<16)|(cuerpo[o+2]<<8)|cuerpo[o+3]) >>> 0; o += 4;
      if (o + origLen > cuerpo.length) return { ok: false, error: 'v4 truncado (data)' };
      let data = cuerpo.slice(o, o + origLen); o += origLen;

      
      if (flags & FLAG_ANTES) {
        if (!key) return { ok: false, error: 'Necesita contraseña', cifrado: true };
        const nonce = new Uint8Array(salt.length + 1);
        nonce.set(salt, 0);
        nonce[salt.length] = tipo;
        try { data = descifrarCapa3(data, key, nonce); }
        catch (e) { return { ok: false, error: 'Fallo descifrado item', cifrado: true }; }
      }

      items.push({ ver, tipo, name, origLen, crc, data });
    }
    return { ok: true, cifrado, flags, items };
  }

  return { ok: false, error: 'Versión desconocida: ' + ver };
}


function byteToVS(b) { return b < 240 ? (0xE0100 + b) : (0xFE00 + (b - 240)); }
function vsToByte(cp) {
  if (cp >= 0xE0100 && cp <= 0xE01EF) return cp - 0xE0100;
  if (cp >= 0xFE00 && cp <= 0xFE0F) return 240 + (cp - 0xFE00);
  return -1;
}

// ============================================================
// GUARDIÁN (SIN TOCAR)
// ============================================================
function guardianRecorta(str) {
  const bytes = [];
  let idx = 0;
  let cortado = false;
  let motivo = null;
  let primeraFachadaVista = false;
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    const b = vsToByte(cp);
    if (b >= 0) { bytes.push(b); primeraFachadaVista = true; }
    else {
      cortado = true;
      if (!primeraFachadaVista) motivo = 'nada antes del primer byte raro';
      else motivo = 'byte no-VS después de la cola';
      if (!motivo) motivo = 'byte raro en idx ' + idx;
    }
    idx++;
  }
  return { bytes: new Uint8Array(bytes), cortado, motivo, idx };
}
function vsStringToBytes(str) { return guardianRecorta(str).bytes; }

// ============================================================
// SABIAS QUE COMENTE ESTE CODIGO EN UNA NOCHE ¿CIERTO? Eso espero porqué más obvio imposible
// ============================================================
function detectMime(b) {
  if (b.length < 12) return { mime: 'application/octet-stream', ext: 'bin', tipo: 'binario' };
  if (b[0]===0xFF && b[1]===0xD8 && b[2]===0xFF) return { mime: 'image/jpeg', ext: 'jpg', tipo: 'imagen JPG' };
  if (b[0]===0x89 && b[1]===0x50 && b[2]===0x4E && b[3]===0x47) return { mime: 'image/png', ext: 'png', tipo: 'imagen PNG' };
  if (b[0]===0x47 && b[1]===0x49 && b[2]===0x46) return { mime: 'image/gif', ext: 'gif', tipo: 'imagen GIF' };
  if (b[0]===0x52 && b[1]===0x49 && b[2]===0x46 && b[3]===0x46 && b[8]===0x57 && b[9]===0x45 && b[10]===0x42 && b[11]===0x50) return { mime: 'image/webp', ext: 'webp', tipo: 'imagen WebP' };
  if (b[4]===0x66 && b[5]===0x74 && b[6]===0x79 && b[7]===0x70) return { mime: 'video/mp4', ext: 'mp4', tipo: 'video MP4' };
  if (b[0]===0x1A && b[1]===0x45 && b[2]===0xDF && b[3]===0xA3) return { mime: 'video/webm', ext: 'webm', tipo: 'video WebM' };
  if (b[0]===0x25 && b[1]===0x50 && b[2]===0x44 && b[3]===0x46) return { mime: 'application/pdf', ext: 'pdf', tipo: 'PDF' };
  if (b[0]===0x50 && b[1]===0x4B) return { mime: 'application/zip', ext: 'zip', tipo: 'ZIP/APK/DOCX' };
  if (b[0]===0x49 && b[1]===0x44 && b[2]===0x33) return { mime: 'audio/mpeg', ext: 'mp3', tipo: 'audio MP3' };
  if (b[0]===0x4F && b[1]===0x67 && b[2]===0x67 && b[3]===0x53) return { mime: 'audio/ogg', ext: 'ogg', tipo: 'audio OGG' };
  if (b[0]===0x52 && b[1]===0x49 && b[2]===0x46 && b[3]===0x46) return { mime: 'audio/wav', ext: 'wav', tipo: 'audio WAV' };
  return { mime: 'application/octet-stream', ext: 'bin', tipo: 'binario' };
}

const $ = id => document.getElementById(id);
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n/1024).toFixed(1) + ' KB' : (n/1048576).toFixed(2) + ' MB';
function setOut(id, html, cls) { const el = $(id); el.className = 'out ' + (cls || ''); el.innerHTML = html; }

document.querySelectorAll('nav button').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('section').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    $(b.dataset.tab).classList.add('active');
  });
});

async function copyRobusto(texto) {
  try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(texto); return { ok: true, modo: 'clipboard' }; } } catch (e) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = texto; ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;width:2px;height:2px;padding:0;border:none;outline:none;background:transparent;font-size:16px';
    document.body.appendChild(ta); ta.focus(); ta.select(); ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy'); document.body.removeChild(ta);
    if (ok) return { ok: true, modo: 'execCommand' };
  } catch (e) {}
  return { ok: false };
}
function selTodo(el) { try { const r = document.createRange(); r.selectNodeContents(el); const s = window.getSelection(); s.removeAllRanges(); s.addRange(r); } catch (e) {} }

// ============================================================
// Sistema de items dinámicos en Empaquetar, sí esta es la segunda pista que te deje, el resto del codigo esta vacío
// ============================================================
function crearItemHTML() {
  return `
    <div class="pack-item">
      <div class="row">
        <label>Tipo</label>
        <select class="item-tipo">
          <option value="archivo">Archivo</option>
          <option value="texto">Texto</option>
          <option value="url">URL / Link</option>
        </select>
        <button class="action item-remove" title="Quitar">✕</button>
      </div>
      <div class="row item-row-archivo">
        <label>Archivo</label>
        <input accept= ".jpg, .png, .docx, .gif, .mp4, .mp3, .pdf, .wav,  .m4a, .zip, .apk, .html, .xml, .css, .js" type="file" class="item-file">
      </div>
      <div class="row item-row-texto" style="display:none">
        <label>Texto</label>
        <textarea class="item-texto" placeholder="Escribí el texto..." style="min-height:70px"></textarea>
      </div>
      <div class="row item-row-url" style="display:none">
        <label>URL</label>
        <input type="text" class="item-url" placeholder="https://...">
      </div>
    </div>`;
}
function setupItem(el) {
  const tipoSel = el.querySelector('.item-tipo');
  const rArch = el.querySelector('.item-row-archivo');
  const rTxt  = el.querySelector('.item-row-texto');
  const rUrl  = el.querySelector('.item-row-url');
  const btnRm = el.querySelector('.item-remove');
  function update() {
    const t = tipoSel.value;
    rArch.style.display = (t === 'archivo') ? 'flex' : 'none';
    rTxt.style.display  = (t === 'texto')   ? 'flex' : 'none';
    rUrl.style.display  = (t === 'url')     ? 'flex' : 'none';
  }
  tipoSel.addEventListener('change', update);
  btnRm.addEventListener('click', () => {
    const cont = $('pack-items');
    if (cont.children.length <= 1) { setOut('pack-out', 'Debe quedar al menos 1 elemento.', 'info'); return; }
    el.remove();
  });
  update();
}
function addItem() {
  const cont = $('pack-items');
  const wrap = document.createElement('div');
  wrap.innerHTML = crearItemHTML();
  const item = wrap.firstElementChild;
  cont.appendChild(item);
  setupItem(item);
}
addItem();
$('pack-add').addEventListener('click', addItem);

// ============================================================
// JAJAJJAJ, Y HASTA ME CREISTE CABRÓN
// ============================================================
function actualizarCifradoUI() {
  const modo = $('pack-cifrado').value;
  const visible = (modo !== 'none');
  $('pack-row-password').style.display = visible ? 'flex' : 'none';
  $('pack-row-iter').style.display = visible ? 'flex' : 'none';
}
$('pack-cifrado').addEventListener('change', actualizarCifradoUI);
actualizarCifradoUI();

let lastStr = null;

$('pack-go').addEventListener('click', async () => {
  
  if (!window.Api || !window.Api.estaLogueado()) {
    setOut('pack-out', 'Tenés que iniciar sesión.', 'err');
    return;
  }

  // Consumir uso si es gratuito
  const uso = await consumirUso();
  if (!uso.ok) {
    setOut('pack-out', '✗ ' + (uso.error || 'Sin usos restantes'), 'err');
    return;
  }

  setOut('pack-out', 'Procesando...');
  
  
  $('pack-stats').textContent = '';
  $('pack-prev').textContent = '—'; $('pack-prev').classList.remove('small');
  lastStr = null;
  $('pack-copy').disabled = true; $('pack-copy-parts').disabled = true; $('pack-select').disabled = true;

  try {
    const emojiChar = $('pack-emoji-espacio')?.checked ? '' : $('pack-emoji').value;
    const modo = $('pack-cifrado').value;
    const password = $('pack-password').value;
    const iteraciones = parseInt($('pack-iter').value, 10) || 5000;

    if (modo !== 'none' && !password) {
      setOut('pack-out', 'Elegiste cifrado pero no pusiste contraseña.', 'err'); return;
    }

    const itemEls = document.querySelectorAll('#pack-items .pack-item');
    if (itemEls.length === 0) { setOut('pack-out', 'Añadí al menos un elemento.', 'err'); return; }

    const items = [];
    let totalOriginal = 0;

    for (const el of itemEls) {
      const tipo = el.querySelector('.item-tipo').value;
      if (tipo === 'archivo') {
        const f = el.querySelector('.item-file').files[0];
        if (!f) { setOut('pack-out', 'Falta un archivo en uno de los items.', 'err'); return; }
        const data = new Uint8Array(await f.arrayBuffer());
        items.push({ nombre: f.name, tipo: TIPO_ARCHIVO, data, origLen: data.length, crc: crc32(data) });
        totalOriginal += data.length;
      } else if (tipo === 'texto') {
        const t = el.querySelector('.item-texto').value;
        if (!t) { setOut('pack-out', 'Falta un texto en uno de los items.', 'err'); return; }
        const data = new TextEncoder().encode(t);
        items.push({ nombre: 'texto.txt', tipo: TIPO_TEXTO, data, origLen: data.length, crc: crc32(data) });
        totalOriginal += data.length;
      } else if (tipo === 'url') {
        const u = el.querySelector('.item-url').value.trim();
        if (!u) { setOut('pack-out', 'Falta una URL en uno de los items.', 'err'); return; }
        const data = new TextEncoder().encode(u);
        items.push({ nombre: 'url.txt', tipo: TIPO_URL, data, origLen: data.length, crc: crc32(data) });
        totalOriginal += data.length;
      }
    }

    let payload;
    let cifradoInfo;
    if (modo === 'none') {
      payload = buildPayloadV3(items);
      cifradoInfo = null;
    } else {
      payload = buildPayloadV4(items, password, modo, iteraciones);
      cifradoInfo = modo;
    }

    const CHUNK = 40000;
    const totalChunks = Math.ceil(payload.length / CHUNK);
    const parts = [];
    for (let c = 0; c < totalChunks; c++) {
      const s = c * CHUNK, e = Math.min(s + CHUNK, payload.length);
      let str = emojiChar;
      for (let i = s; i < e; i++) str += String.fromCodePoint(byteToVS(payload[i]));
      parts.push(str);
    }
    lastStr = parts.join('\n');

    const g = guardianRecorta(lastStr);
    $('pack-prev').textContent = emojiChar || '(sin fachada)';

    if (g.cortado) {
      setOut('pack-out', `ℹ️ Guardián reportó: ${g.motivo}\nBytes válidos: ${g.bytes.length}\nEl CRC decidirá si llegó bien.`, 'info');
    } else {
      const cifTxt = cifradoInfo ? ` · cifrado: ${cifradoInfo}` : ' · sin cifrado';
      setOut('pack-out', `✓ Listo · ${items.length} item(s) · ${totalChunks} bloque(s) · payload ${fmtSize(payload.length)}${cifTxt}`, 'ok');
    }
    $('pack-copy').disabled = false; $('pack-copy-parts').disabled = false; $('pack-select').disabled = false;

    let detalle = '';
    items.forEach((it, i) => {
      const tName = it.tipo === TIPO_ARCHIVO ? 'archivo' : it.tipo === TIPO_TEXTO ? 'texto' : 'url';
      detalle += `  ${i + 1}. ${tName} · ${it.nombre} · ${fmtSize(it.origLen)} · CRC ${it.crc.toString(16).padStart(8,'0')}\n`;
    });

    $('pack-stats').innerHTML =
      `<b>Items:</b>       ${items.length}\n` +
      `<b>Original:</b>    ${fmtSize(totalOriginal)} (suma)\n` +
      `<b>Payload:</b>     ${fmtSize(payload.length)}\n` +
      `<b>Overhead:</b>    ${(payload.length - totalOriginal)} bytes\n` +
      `<b>Bloques:</b>     ${totalChunks}\n` +
      `<b>Cifrado:</b>     ${cifradoInfo || 'ninguno'}\n` +
      `<b>Fachada:</b>     ${emojiChar || '(ninguna)'}\n` +
      `<b>Guardián:</b>    ${g.cortado ? 'REPORTÓ · ' + g.motivo : 'OK · ' + g.bytes.length + ' bytes válidos'}\n` +
      `<b>Detalle:</b>\n${detalle}`;
  } catch (e) {
    setOut('pack-out', 'Error: ' + e.message, 'err');
  }
});

$('pack-copy').addEventListener('click', async () => {
  if (!lastStr) return;
  setOut('pack-out', 'Copiando...', 'info');
  const r = await copyRobusto(lastStr);
  if (r.ok) { setOut('pack-out', `✓ Copiado (${r.modo}). Pegalo donde quieras.`, 'ok'); return; }
  $('pack-prev').textContent = lastStr; $('pack-prev').classList.add('small'); selTodo($('pack-prev'));
  setOut('pack-out', '⚠️ No pude copiar automáticamente.\n\nEl texto ya está seleccionado abajo. Mantené presionado y elegí "Copiar".', 'err');
});

$('pack-copy-parts').addEventListener('click', async () => {
  if (!lastStr) return;
  const PART = 30000;
  const parts = [];
  for (let i = 0; i < lastStr.length; i += PART) parts.push(lastStr.slice(i, i + PART));
  setOut('pack-out', `Copiando parte 1 de ${parts.length}...`, 'info');
  const r = await copyRobusto(parts[0]);
  if (r.ok) setOut('pack-out', `✓ Parte 1 de ${parts.length} copiada.`, 'ok');
  else setOut('pack-out', 'No pude copiar. Probá "Seleccionar todo".', 'err');
});

$('pack-select').addEventListener('click', () => {
  if (!lastStr) return;
  $('pack-prev').textContent = lastStr; $('pack-prev').classList.add('small'); selTodo($('pack-prev'));
  setOut('pack-out', '✓ Texto seleccionado abajo.\n\nMantené presionado y elegí "Copiar".', 'info');
});


$('unpack-go').addEventListener('click', () => {
  $('unpack-items').innerHTML = '';
  setOut('unpack-out', 'Buscando payload...');

  try {
    const str = $('unpack-str').value.trim();
    if (!str) { setOut('unpack-out', 'Pegá un emoji.', 'err'); return; }

    const password = $('unpack-password').value;
    const g = guardianRecorta(str);
    const allBytes = g.bytes;
    const info = g.cortado ? `ℹ️ Guardián reportó: ${g.motivo}\nIntentando reconstruir igual.\n\n` : '';

    if (allBytes.length < 20) { setOut('unpack-out', info + `El texto no lleva payload (solo ${allBytes.length} bytes).`, 'err'); return; }

    let off = -1;
    for (let i = 0; i + 4 <= allBytes.length; i++) {
      if (allBytes[i]===0x45 && allBytes[i+1]===0x4D && allBytes[i+2]===0x46 && allBytes[i+3]===0x47) { off = i; break; }
    }
    if (off < 0) { setOut('unpack-out', info + 'No encontré la firma EMFG.', 'err'); return; }

    const payload = allBytes.slice(off);
    const resultado = parsePayload(payload, password);

    if (!resultado.ok) {
      if (resultado.cifrado) {
        setOut('unpack-out', info + '🔒 Este payload está cifrado.\n' + (resultado.error === 'Necesita contraseña' ? 'Ingresá la contraseña arriba y volvé a intentar.' : 'Contraseña incorrecta o datos corruptos.'), 'err');
      } else {
        setOut('unpack-out', info + '✗ ' + resultado.error, 'err');
      }
      return;
    }

    const items = resultado.items;
    if (!items || items.length === 0) { setOut('unpack-out', info + 'Payload vacío.', 'err'); return; }

    const cont = $('unpack-items');
    let todosOk = true;

    items.forEach((p, idx) => {
      const fileBytes = p.data;
      const crcObt = crc32(fileBytes);
      const ok = crcObt === p.crc;
      const sizeOk = fileBytes.length === p.origLen;
      if (!ok) todosOk = false;

      let det;
      if (p.tipo === TIPO_TEXTO) det = { mime: 'text/plain', ext: 'txt', tipo: 'texto' };
      else if (p.tipo === TIPO_URL) det = { mime: 'text/plain', ext: 'txt', tipo: 'url' };
      else det = detectMime(fileBytes);

      let nombreSalida = p.name || ('archivo.' + det.ext);
      if (p.tipo === TIPO_ARCHIVO && !/\.[a-z0-9]{1,6}$/i.test(nombreSalida)) nombreSalida += '.' + det.ext;

      const card = document.createElement('div');
      card.className = 'item-card';

      const title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = `📎 ${idx + 1}. ${p.name || '(sin nombre)'}`;
      card.appendChild(title);

      const meta = document.createElement('div');
      meta.className = 'card-meta';
      meta.textContent = `${det.tipo} · orig ${fmtSize(p.origLen)} · reconst ${fmtSize(fileBytes.length)} · CRC ${crcObt.toString(16).padStart(8,'0')}`;
      card.appendChild(meta);

      const body = document.createElement('div');
      body.className = 'card-body';

      if (p.tipo === TIPO_TEXTO) {
        const pre = document.createElement('pre');
        pre.textContent = new TextDecoder().decode(fileBytes);
        body.appendChild(pre);
} else if (p.tipo === TIPO_URL) {
  const url = new TextDecoder().decode(fileBytes);
  const esSegura = /^(https?|mailto|tel):/i.test(url.trim());
  if (esSegura) {
    const a = document.createElement('a');
    a.href = url; a.target = '_blank'; a.rel = 'noopener'; a.textContent = url;
    body.appendChild(a);
  } else {
    const pre = document.createElement('pre');
    pre.textContent = url;
    body.appendChild(pre);}
} else if (det.mime.startsWith('image/')) {
        const blob = new Blob([fileBytes], { type: det.mime });
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img'); img.src = url;
        img.onload = () => URL.revokeObjectURL(url);
        body.appendChild(img);
      } else if (det.mime.startsWith('video/')) {
        const blob = new Blob([fileBytes], { type: det.mime });
        const url = URL.createObjectURL(blob);
        const vid = document.createElement('video'); vid.src = url; vid.controls = true;
        body.appendChild(vid);
      }
      card.appendChild(body);

      const status = document.createElement('div');
      status.className = 'card-status ' + (ok ? 'ok' : 'err');
      status.textContent = ok
        ? `✓ ÍNTEGRO${sizeOk ? '' : ' (tamaño no coincide)'}`
        : `✗ CORRUPTO (CRC no coincide)`;
      card.appendChild(status);

      const btnRow = document.createElement('div');
btnRow.style.cssText = 'display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap';

const btn = document.createElement('button');
btn.className = 'card-dl';
btn.style.flex = '1';
btn.textContent = `💾 Guardar ${nombreSalida}`;
btn.addEventListener('click', () => {
  const blob = new Blob([fileBytes], { type: det.mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = nombreSalida;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
btnRow.appendChild(btn);

const btnCopy = document.createElement('button');
btnCopy.className = 'card-dl';
btnCopy.style.flex = '1';
btnCopy.style.background = '#4a6cf7';
btnCopy.textContent = `📋 Copiar ${nombreSalida}`;
btnCopy.addEventListener('click', async () => {
  let texto = '';
  if (p.tipo === TIPO_TEXTO || p.tipo === TIPO_URL) {
    texto = new TextDecoder().decode(fileBytes);
  } else if (det.mime.startsWith('image/') || det.mime.startsWith('video/')) {
    texto = new TextDecoder().decode(fileBytes);
  } else {
    texto = new TextDecoder().decode(fileBytes);
  }
  const r = await copyRobusto(texto);
  if (r.ok) {
    btnCopy.textContent = `✓ Copiado`;
    setTimeout(() => { btnCopy.textContent = `📋 Copiar ${nombreSalida}`; }, 1500);
  } else {
    btnCopy.textContent = `⚠️ No se pudo`;
    setTimeout(() => { btnCopy.textContent = `📋 Copiar ${nombreSalida}`; }, 1500);
  }
});
btnRow.appendChild(btnCopy);

card.appendChild(btnRow);

      cont.appendChild(card);
    });

    const cifTxt = resultado.cifrado ? ' · 🔒 descifrado' : '';
    $('unpack-stats').innerHTML =
      `<b>Items:</b>       ${items.length}\n` +
      `<b>Cifrado:</b>     ${resultado.cifrado ? 'sí' + (resultado.flags ? ' (flags=' + resultado.flags + ')' : '') : 'no'}\n` +
      `<b>Guardián:</b>    ${g.cortado ? 'REPORTÓ · ' + g.motivo : 'OK · ' + g.bytes.length + ' bytes válidos'}\n` +
      `<b>Estado:</b>      ${todosOk ? 'TODOS ÍNTEGROS ✓' : 'ALGUNO CORRUPTO ✗'}`;

    if (todosOk) {
      const sufijo = g.cortado ? ' (con reporte del guardián, pero bytes íntegros)' : '';
      setOut('unpack-out', `✓ Extraídos ${items.length} item(s)${cifTxt} · byte por byte idénticos` + sufijo, 'ok');
    } else {
      setOut('unpack-out', info + '✗ Al menos un item no coincide en CRC', 'err');
    }
  } catch (e) {
    setOut('unpack-out', 'Error: ' + e.message, 'err');
  }
});

// ============================================================
// SESIÓN · LOGIN · HEADER DE USUARIO, te recomiendo revisar esta parte
// ============================================================

function mostrarLogin() {
  document.body.classList.remove('autenticado');
  document.body.classList.add('no-autenticado');
 if (window.AdminPanel) window.AdminPanel.desactivar();
}

 async function mostrarApp() {
  const usuario = sessionStorage.getItem('emojiforge_usuario') || '';
const rol = window.Api.rol || '';
if (window.marcarAutenticado) {
window.marcarAutenticado(usuario, rol);
} else {
document.body.classList.remove('no-autenticado');
document.body.classList.add('autenticado');
}
if (window.AdminPanel) {
   if(rol === 'ADMIN') {
   await window.AdminPanel.activar();
}else { window.AdminPanel.desactivar();

   }
}
actualizarHeaderUsuario();
}


async function actualizarHeaderUsuario() {
  const nombreEl = document.getElementById('usuario-nombre');
  const rolEl = document.getElementById('usuario-rol');
  const usosEl = document.getElementById('usuario-usos');
  if (!nombreEl || !rolEl || !usosEl) return;

try
{
const r = await window.Api.miPerfil();
if ( r && r.ok) {
nombreEl.textContent = r.nombre || '-';
rolEl.textContent = r.rol || window.Api.rol || '-';
if (typeof r.usosRestantes === 'number' && r.usosRestantes >= 0) {
usosEl.textContent = 'Usos: ' + r.usosRestantes;
} else{
usosEl.textContent = '';
}
try {
sessionStorage.setItem ('emojiforge_usuario', r.nombre || '');
if (r.rol) sessionStorage.setItem('emojiforge_rol', r.rol);

} catch (e) {}
  }
 } catch (e) {}
}


// ------------------------------------------------------------
//  ESTA NO TE RECOMIENDO, REALMENTE NO SACAS MUCHO
// ------------------------------------------------------------
const loginGo = document.getElementById('login-go');
if (loginGo) {
  loginGo.addEventListener('click', async () => {
    const nombre = (document.getElementById('login-nombre').value || '').trim();
    const password = document.getElementById('login-password').value || '';
    const out = document.getElementById('login-out');

    if (!nombre || !password) {
      out.className = 'out err';
      out.textContent = 'Completá nombre y contraseña.';
      return;
    }

    out.className = 'out info';
    out.textContent = 'Entrando...';

    const r = await window.Api.login(nombre, password);
if (r && r.ok) {
  out.className = 'out ok';
  out.textContent = '✓ Entraste.';
  document.getElementById('login-password').value = '';
  mostrarApp();
}
    else {
      out.className = 'out err';
      out.textContent = (r && r.error) ? r.error : 'Credenciales incorrectas.';
    }
  });
}


const loginCrear = document.getElementById('login-crear');
if (loginCrear) {
  loginCrear.addEventListener('click', async () => {
    const nombre = (document.getElementById('login-nombre').value || '').trim();
    const password = document.getElementById('login-password').value || '';
    const out = document.getElementById('login-out');

    if (!nombre || !password) {
      out.className = 'out err';
      out.textContent = 'Completá nombre y contraseña.';
      return;
    }

    out.className = 'out info';
    out.textContent = 'Creando perfil...';
const r = await window.Api.crearPerfilGratuito(nombre, password);
if (r && r.ok) {
  out.className = 'out ok';
  out.textContent = '✓ Entraste.';
  document.getElementById('login-password').value = '';
  mostrarApp();
} 
    else {
  out.className = 'out err';
  out.textContent = (r && r.error) ? r.error : 'Credenciales incorrectas.';
  // Limpiar la contraseña también en el fallo
  document.getElementById('login-password').value = '';
}
    
  });
}

// ------------------------------------------------------------
// Logout
// ------------------------------------------------------------
const btnLogout = document.getElementById('btn-logout');
if (btnLogout) {
  btnLogout.addEventListener('click', async () => {
    await window.Api.logout();
    mostrarLogin();
    const out = document.getElementById('login-out');
    if (out) {
      out.className = 'out';
      out.textContent = 'Esperando...';
    }
  });
}


const loginPass = document.getElementById('login-password');
if (loginPass) {
  loginPass.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const b = document.getElementById('login-go');
      if (b) b.click();
    }
  });
}


async function consumirUso() {
  if (window.Api.rol !== 'GRATUITO') return { ok: true };
  try {
    const r = await window.Api.request('/api/consumir-uso', { method: 'POST' });
    if (r && r.ok) return { ok: true };
    // Si el endpoint todavía no existe (404), no bloqueamos
    if (r && r.status === 404) return { ok: true };
    return { ok: false, error: (r && r.error) || 'Sin usos restantes' };
  } catch (e) {
    return { ok: true };
  }
}

// ------------------------------------------------------------
//  EN EL PROXIMO LOS COMENTARIOS NO SERÁN TAN ELAVORADOS
// ------------------------------------------------------------
async function arrancarSesion() {
  if (!window.Api) {
    mostrarLogin();
    return;
  }
  if (window.Api.estaLogueado()) {
    // Verifica el token contra el server
    const r = await window.Api.miPerfil();
    if (r && r.ok) {
        if (r.rol) window.Api.rol = r.rol;
      mostrarApp();
    } else {
      window.Api.borrarToken();
      mostrarLogin();
    }
  } else {
    mostrarLogin();
  }
}

arrancarSesion();

