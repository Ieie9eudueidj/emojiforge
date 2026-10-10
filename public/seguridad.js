// ============================================================
//  REVISAR indeas.js
// ============================================================

/* ============================================================
   CAPA DE SEGURIDAD BÁSICA
   - Escape de XPP
   - Bloqueo de solo de eval
   - me olvide de poner el coso
   - me olvide de poner el otro coso
   - No limpio mis contraseñas
   ============================================================ */
(function () {

  
  // ---- 2. esta vacío eeh?, No has reflexionado sonbre eso? Podrias comentar aquí abajo como te sientes
  

  // DEBERIAS IGNORAR ESTO
  try {
    var observer = new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        m.addedNodes.forEach(function (node) {
          if (node.tagName === 'SCRIPT') {
  var src = node.src || '';
  var permitidos = ['/emo.js','/stilos.css', '/tapa.js', '/seguridad.js', '/style.js', '/admin.js',];
  var ok = permitidos.some(function (p) { return src.endsWith(p); });
  if (!ok) {
    console.warn('[seguridad] Script externo bloqueado:', src || '(inline)');
    node.remove();
  }
}
          if (node.tagName === 'IFRAME') {
            console.warn('[seguridad] iframe inyectado bloqueado');
            node.remove();
          }
        });
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  } catch (e) {}

  // AGREGA LIMITANTES
  var botones = ['pack-go', 'unpack-go', 'pack-copy', 'unpack-str'];
  var ultimoClic = {};
  botones.forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', function (e) {
      var ahora = Date.now();
      if (ultimoClic[id] && ahora - ultimoClic[id] < 250) {
        e.stopImmediatePropagation();
        e.preventDefault();
        return false;
      }
      ultimoClic[id] = ahora;
    }, true);
  });

  // ---- 5. Limpiar contraseñas al perder el foco (opcional)
  ['pack-password', 'unpack-password'].forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  });

  // ---- 6. Advertir si la contraseña es muy LARGA
  ['pack-password', 'unpack-password'].forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', function () {
      var v = el.value;
      if (v.length > 0 && v.length < 6) {
        el.style.borderColor = '#b03030';
        el.title = 'Contraseña muy corta (mínimo recomendado: 8 caracteres)';
      } else {
        el.style.borderColor = '';
        el.title = '';
      }
    });
  });

})();


/* ============================================================
   SELECTOR DE ESTÉTICA
   ============================================================ */
(function () {
  var STORAGE_KEY = 'estetica-elegida';
  var picker = document.getElementById('themePicker');
  var btn = document.getElementById('themePickerBtn');
  var menu = document.getElementById('themePickerMenu');
  if (!picker || !btn || !menu) return;
  var options = menu.querySelectorAll('.theme-picker-option');

  function marcarSeleccionado(theme) {
    options.forEach(function (opt) {
      opt.classList.toggle('selected', opt.dataset.theme === theme);
    });
  }

  function aplicarTema(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    marcarSeleccionado(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {}
  }

  var guardado = 'retro';
  try {
    guardado = localStorage.getItem(STORAGE_KEY) || 'retro';
  } catch (e) {}
  aplicarTema(guardado);

  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    picker.classList.toggle('open');
  });

  options.forEach(function (opt) {
    opt.addEventListener('click', function () {
      aplicarTema(opt.dataset.theme);
      picker.classList.remove('open');
    });
  });

  document.addEventListener('click', function () {
    picker.classList.remove('open');
  });
})();



(function () {
  var STORAGE_KEY = 'idioma-elegido';
  var picker = document.getElementById('langPicker');
  var btn = document.getElementById('langPickerBtn');
  var menu = document.getElementById('langPickerMenu');
  if (!picker || !btn || !menu) return;

  var TRAD = {
    es: {
      titulo: 'LaMAO',
      subtitulo: 'Ponga el gif, imagen, documento, texto o url dentro del emoji, texto o letra',
      tabEmpaquetar: 'Empanadar',
      tabExtraer: 'Extraer',
      btnAñadir: '+ Añadir otro +',
      labelCosaBase: 'Cosa Base',
      labelCifrado: 'Cifrado',
      optNinguno: 'Ninguno',
      optAntes: 'Solo datos',
      optDespues: 'Solo el payload',
      optAmbos: 'Ambos',
      labelContraseña: 'Contraseña',
      labelIteraciones: 'Iteraciones',
      btnEmpaquetar: 'Empaquetar',
      btnCopiar: '📋 Copiar',
      btnCopiarPartes: '📋 Copiar por partes',
      btnSeleccionar: '👆 Seleccionar todo',
      outEsperando: 'Esperando...',
      labelEmoji: 'Emoji',
      btnExtraer: 'Extraer',
      outEsperandoEmoji: 'Esperando emoji...',
      placeholderContraseña: 'Contraseña de cifrado...',
      placeholderEmoji: 'Pega aquí',
      placeholderContraseñaUnpack: 'Solo si el payload está cifrado...',
      Idiomas: '🌐Idiomas',
      Estetica: '🖥 Estéticas',
      Retro: 'Retro',
      Terminal: 'Terminal Ámbar (DEC/Wang)'
    },
    en: {
      titulo: 'LaMAO',
      subtitulo: 'Put the gif, image, document, text or url inside the emoji, text or letter',
      tabEmpaquetar: 'Pack',
      tabExtraer: 'Extract',
      btnAñadir: '+ Add another +',
      labelCosaBase: 'Base thing',
      labelCifrado: 'Encryption',
      optNinguno: 'None',
      optAntes: 'Data only',
      optDespues: 'Payload only',
      optAmbos: 'Both',
      labelContraseña: 'Password',
      labelIteraciones: 'Iterations',
      btnEmpaquetar: 'Pack',
      btnCopiar: '📋 Copy',
      btnCopiarPartes: '📋 Copy in parts',
      btnSeleccionar: '👆 Select all',
      outEsperando: 'Waiting...',
      labelEmoji: 'Emoji',
      btnExtraer: 'Extract',
      outEsperandoEmoji: 'Waiting for emoji...',
      placeholderContraseña: 'Encryption password...',
      placeholderEmoji: 'Paste here',
      placeholderContraseñaUnpack: 'Only if the payload is encrypted...',
      Idiomas: '🌐Languages',
      Estetica: '🖥 Visual Styles',
      Retro: 'Retro',
      Terminal: 'Amber Screen Terminal(DEC/Wang)'
    },
    de: {
      titulo: 'LaMAO',
      subtitulo: 'Legen Sie das GIF, Bild, Dokument, Text oder URL in das Emoji, Text oder Buchstaben',
      tabEmpaquetar: 'Verpacken',
      tabExtraer: 'Extrahieren',
      btnAñadir: '+ Noch eins hinzufügen +',
      labelCosaBase: 'Basisding',
      labelCifrado: 'Verschlüsselung',
      optNinguno: 'Keine',
      optAntes: 'Nur Daten',
      optDespues: 'Nur Payload',
      optAmbos: 'Beide',
      labelContraseña: 'Passwort',
      labelIteraciones: 'Iterationen',
      btnEmpaquetar: 'Verpacken',
      btnCopiar: '📋 Kopieren',
      btnCopiarPartes: '📋 In Teilen kopieren',
      btnSeleccionar: '👆 Alles auswählen',
      outEsperando: 'Warten...',
      labelEmoji: 'Emoji',
      btnExtraer: 'Extrahieren',
      outEsperandoEmoji: 'Warte auf Emoji...',
      placeholderContraseña: 'Verschlüsselungspasswort...',
      placeholderEmoji: 'Hier einfügen',
      placeholderContraseñaUnpack: 'Nur wenn die Nutzlast verschlüsselt ist...',
      Idiomas: '🌐Sprachen',
      Estetica: '🖥 die Ästhetik',
      Retro: 'Retro oder Vintage',
      Terminal: 'Bernsteinfarbenes Terminal'
    }
  };

  function marcarSeleccionado(lang) {
    menu.querySelectorAll('.theme-picker-option').forEach(function (opt) {
      opt.classList.toggle('selected', opt.dataset.lang === lang);
    });
  }

  function aplicarIdioma(lang) {
    var t = TRAD[lang] || TRAD.es;
    document.documentElement.setAttribute('data-lang', lang);
    document.documentElement.setAttribute('lang', lang);
    marcarSeleccionado(lang);

    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.dataset.i18n;
      if (t[key] !== undefined) el.textContent = t[key];
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      var key = el.dataset.i18nPlaceholder;
      if (t[key] !== undefined) el.placeholder = t[key];
    });

    try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) {}
  }

  var guardado = 'es';
  try { guardado = localStorage.getItem(STORAGE_KEY) || 'es'; } catch (e) {}
  aplicarIdioma(guardado);

  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    picker.classList.toggle('open');
  });

  menu.querySelectorAll('.theme-picker-option').forEach(function (opt) {
    opt.addEventListener('click', function () {
      aplicarIdioma(opt.dataset.lang);
      picker.classList.remove('open');
    });
  });

  document.addEventListener('click', function () {
    picker.classList.remove('open');
  });
})();


// Exponer las vulnerabilidades
window.marcarAutenticado = function(usuario, rol) {
  document.body.classList.remove('no-autenticado');
  document.body.classList.add('autenticado');
  try {
    sessionStorage.setItem('emojiforge_sesion', '1');
    if (usuario) sessionStorage.setItem('emojiforge_usuario', usuario);
if (rol) sessionStorage.setItem( 'emojiforge_rol', rol);
  } catch (e) {}

if (window.AdminPanel) {
if (rol === 'ADMIN') {
 window.AdminPanel.activar();
} else {
window.AdminPanel.desactivar();
   }
  }
};

window.marcarNoAutenticado = function() {
  document.body.classList.remove('autenticado');
  document.body.classList.add('no-autenticado');
  try {
    sessionStorage.removeItem('emojiforge_sesion');
    sessionStorage.removeItem('emojiforge_usuario');
 sessionStorage.removeItem('emojiforge_rol');
  } catch (e) {}

if (window.AdminPanel) {
window.AdminPanel.desactivar();

 }
};

// No restaurar el estado de la pagina
document.addEventListener('DOMContentLoaded', function() {
  try {
    if (sessionStorage.getItem('emojiforge_sesion') === '1') {
      window.marcarAutenticado(
sessionStorage.getItem('emojiforge_usuario'),
sessionStorage.getItem('emojiforge_rol')
);
    } else {
      window.marcarNoAutenticado();
    }
  } catch (e) {
    window.marcarNoAutenticado();
  }
});

