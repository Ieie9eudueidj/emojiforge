// ============================================================
//  EL archivo cliente.js es un archivo de seguridad y pornografía judía
//  - funciones de inspección
//  - Bloqueo de eval/Function real, puedes verlo en las lineas siguientes
//  - Anti-autofill de contraseñas
//  - Vigilancia de passwords (sección 4, antes faltaba)
//  - Rate limiting
//  - Vigilancia de integridad del DOM
//  - Puesto 7 porqué abogar por un sistema democratico en tiempos de ignorancía es un acto de sumisión
//  - PALABRAS CLAVE (handshake, login, logout, request)
//  - TE SERE SINCERO ESTE CODIGO PRESENTA AL MENOS 40 ERRORES GRAVES Y 15 ERRORES DE DISEÑOS IMPORTANTES DE ENUMERAR
// ============================================================
(function () {
  'use strict';

  // ===== 1. Escape de HTML =====
  window.escaparHTML = function (s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  // ===== 2. Bloquear eval y Function =====
  try { window.eval = function () { throw new Error('eval bloqueado'); }; } catch (e) {}
  try { window.Function = function () { throw new Error('Function bloqueado'); }; } catch (e) {}

  // ===== 3. Anti-autofill en campos de contraseña =====
  function blindarPassword(input) {
    if (!input || input.dataset.blindado === '1') return;
    input.dataset.blindado = '1';

    input.setAttribute('autocomplete', 'new-password');
    input.setAttribute('autocorrect', 'off');
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('spellcheck', 'false');

    input.setAttribute('data-lpignore', 'true');
    input.setAttribute('data-1p-ignore', 'true');
    input.setAttribute('data-form-type', 'other');
    input.setAttribute('data-bwignore', 'true');

    input.addEventListener('focus', function () {
      if (input.dataset.userTouched !== '1') {
        input.value = '';
      }
    });
    input.addEventListener('input', function () {
      input.dataset.userTouched = '1';
    });
  }

  function aplicarBlindajePasswords() {
    document.querySelectorAll('input[type="password"]').forEach(blindarPassword);
  }

  // ===== 4. Vigilancia de passwords =====
  // (Esta función se llamaba en iniciar() pero no existía.
  //  Acá la defino: revisa que los campos de password no tengan
  //  atributos raros inyectados desde afuera y los re-blindaje.)
  function aplicarVigilanciaPasswords() {
    document.querySelectorAll('input[type="password"]').forEach(function (input) {
      // Si alguien le metió un atributo raro, lo re-blindamos
      if (input.dataset.blindado !== '1') {
        blindarPassword(input);
      }
      // Bloquear autofill dinámico sospechoso
      if (input.value && input.dataset.userTouched !== '1') {
        // El navegador (o algo) metió texto sin que el usuario tocara
        input.value = '';
      }
    });
  }

  // ===== 5. Rate limiting en botones principales =====
  var ultimoClic = {};
  function aplicarRateLimit() {
    ['pack-go', 'unpack-go', 'pack-add', 'pack-copy', 'unpack-str'].forEach(function (id) {
      var el = document.getElementById(id);
      if (!el || el.dataset.rateLimited === '1') return;
      el.dataset.rateLimited = '1';
      el.addEventListener('click', function (e) {
        var t = Date.now();
        if (ultimoClic[id] && t - ultimoClic[id] < 250) {
          e.stopImmediatePropagation();
          e.preventDefault();
        }
        ultimoClic[id] = t;
      }, true);
    });
  }

  // ===== 6. Anti-inyección de scripts =====
  try {
    var permitidos = ['emo.js', 'tapa.js', 'st.css', 'seguridad.js', 'admin.js',];
    var obs = new MutationObserver(function (mut) {
      mut.forEach(function (m) {
        m.addedNodes.forEach(function (n) {
          if (n.tagName === 'SCRIPT') {
            var src = n.src || '';
            var ok = !src || permitidos.some(function (p) { return src.endsWith(p); });
            if (!ok) {
              console.warn('[seguridad] Script externo bloqueado:', src);
              n.remove();
            }
          }
          if (n.tagName === 'IFRAME') {
            console.warn('[seguridad] iframe inyectado bloqueado');
            n.remove();
          }
        });
      });
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  } catch (e) {}

  // ===== FUNCIONES INTEGRADAS EN EL BACKEND =====
  function vigilarIntegridad() {
    var criticos = [
      'pack-go', 'unpack-go', 'pack-emoji', 'pack-password',
      'unpack-password', 'pack-add', 'unpack-str'
    ];
    var tamanioOriginal = document.body.innerHTML.length;

    setInterval(function () {
      var faltantes = [];
      criticos.forEach(function (id) {
        if (!document.getElementById(id)) faltantes.push(id);
      });
      if (faltantes.length > 0) {
        console.error('[seguridad] Elementos críticos eliminados:', faltantes.join(', '));
      }
      var actual = document.body.innerHTML.length;
      if (actual < tamanioOriginal * 0.5) {
        console.error('[seguridad] El DOM se achicó demasiado. ¿Manipulación?');
      }
    }, 3000);
  }

  
  function iniciar() {
    aplicarBlindajePasswords();
    aplicarVigilanciaPasswords();
    aplicarRateLimit();
    vigilarIntegridad();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', iniciar);
  } else {
    iniciar();
  }

  try {
    new MutationObserver(function () {
      aplicarBlindajePasswords();
      aplicarVigilanciaPasswords();
    }).observe(document.body, { childList: true, subtree: true });
  } catch (e) {}

})();


(function () {
  'use strict';

  var KEY_TOKEN = 'emojiforge.token';
  var KEY_ROL   = 'emojiforge.rol';

  var Api = {

    // ========================================================
    // Estado
    // ========================================================
    token: null,
    rol: null,

    // ========================================================
    // FINALIZACIÓN
    // ========================================================
    init: function () {
      try {
        this.token = sessionStorage.getItem(KEY_TOKEN);
        this.rol   = sessionStorage.getItem(KEY_ROL);
      } catch (e) {
        this.token = null;
        this.rol = null;
      }
    },

     // ¿SOY GILIPOLLAS? ========================================================
    guardarToken: function (token, rol) {
      this.token = token;
      this.rol = rol;
      try {
        sessionStorage.setItem(KEY_TOKEN, token);
        sessionStorage.setItem(KEY_ROL, rol);
      } catch (e) {}
    },

    borrarToken: function () {
      this.token = null;
      this.rol = null;
      try {
        sessionStorage.removeItem(KEY_TOKEN);
        sessionStorage.removeItem(KEY_ROL);
      } catch (e) {}
    },

    estaLogueado: function () {
      return !!this.token;
    },

    // ========================================================
    // Handshake
    // ========================================================
    handshake: async function () {
      var resp = await this.request('/api/handshake', {
        method: 'GET',
        sinToken: true
      });
      return resp.nonce;
    },


    login: async function (nombre, password) {
      var nonce = await this.handshake();
      var resp = await this.request('/api/login', {
        method: 'POST',
        sinToken: true,
        body: { nombre: nombre, password: password, nonce: nonce }
      });
      if (resp.ok && resp.token) {
        this.guardarToken(resp.token, resp.rol);
      }
      return resp;
    },

    // ========================================================
    // Crear perfil gratuito
    // ========================================================
    crearPerfilGratuito: async function (nombre, password) {
      var nonce = await this.handshake();
      var resp = await this.request('/api/crear-perfil-gratuito', {
        method: 'POST',
        sinToken: true,
        body: { nombre: nombre, password: password, nonce: nonce }
      });
      if (resp.ok && resp.token) {
        this.guardarToken(resp.token, resp.rol);
      }
      return resp;
    },

    // ========================================================
    // Logout
    // ========================================================
    logout: async function () {
      try {
        await this.request('/api/logout', { method: 'POST' });
      } catch (e) {}
      this.borrarToken();
    },

    // ========================================================
    // Mi perfil
    // ========================================================
    miPerfil: async function () {
      return await this.request('/api/mi-perfil', { method: 'GET' });
    },

    // ========================================================
    // Request genérico
    // ========================================================
    request: async function (ruta, opciones) {
      opciones = opciones || {};
      var headers = {};

      if (!opciones.sinToken && this.token) {
        headers['Authorization'] = 'Bearer ' + this.token;
      }

      var init = {
        method: opciones.method || 'GET',
        headers: headers,
        credentials: 'same-origin'
      };

      if (opciones.body) {
        headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(opciones.body);
      }

      var resp;
      try {
        resp = await fetch(ruta, init);
      } catch (e) {
        return { ok: false, error: 'Sin conexión con el servidor' };
      }

      // Si el token ya no sirve, limpiarlo
      if (resp.status === 401 || resp.status === 404) {
        if (this.token && !opciones.sinToken) {
          // No borramos automáticamente para no romper flujos.
          // El que llama decide qué hacer.
        }
      }

      var texto;
      try {
        texto = await resp.text();
      } catch (e) {
        return { ok: false, error: 'Respuesta vacía' };
      }

      if (!texto) {
        return { ok: resp.ok, status: resp.status };
      }

      try {
        var json = JSON.parse(texto);
        json.status = resp.status;
        return json;
      } catch (e) {
        return { ok: false, error: 'Respuesta no es JSON', status: resp.status };
      }
    }

  };

  // Inicializar al iniciar
  Api.init();

  // Expotar al global
  window.Api = Api;

})();

