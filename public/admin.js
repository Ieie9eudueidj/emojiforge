(function ()  {
'use strict';


// fachadas

const RUMORES = {

crearPerfiles: '/sys/tuvieja1',
banear: '/sys/tuvieja2',
cambiarRol: '/sys/tuvieja3',
eliminar: '/sys/tuvieja4',
log: '/sys/tuvieja5',
gratuitos: '/sys/tuvieja20',
autobanear: '/sys/tuvieja11',
cambiarIP: '/sys/tuviejaca',
panel: '/sis/panel',
};

//estados

let inicializado = false;

// UT

const $ = (id) => document.getElementById(id);

const esc = (s) => (window.escaparHTML ? window.escaparHTML(s) : String(s == null ? '' : s));

 function setOut(id, html, cls) {
const el = $(id);
if (!el) return;
el.className ='out ' + (cls || ''); 
el.innerHTML = html;
}


// Rojo & Azul

async function activarUIAdmin() {
if (!window.Api || window.Api.rol !== 'ADMIN') return;
if (document.getElementById("A")){
document.body.dataset.rol = 'ADMIN';
return;

}
const r = await window.Api.request(RUMORES.panel, { method: 'GET'});
if (!r || !r.ok || !r.html) return;
document.getElementById('app').insertAdjacentHTML('beforeend', r.html);
conectarBotones();
document.body.dataset.rol = 'ADMIN';
}

 function desactivarUIAdmin () {
 delete document.body.dataset.rol;

const seccion = document.getElementById('A');
    if (seccion) seccion.remove();

    const tabAdmin = document.querySelector('.tab-admin');
    if (tabAdmin && tabAdmin.classList.contains('active')) {
        const primera = document.querySelector('nav button:not(.tab-admin)');
        if (primera) primera.click();
    }

    
}


setOut('admin-crear-out','Esperando...');
setOut('admin-log-out', 'Esperando...'); 
setOut('admin-peligro-out', 'Esperando...');
const listar = $('admin-lista-usuarios');

if (listar) listar.innerHTML = '<div class="admin-vacio">Sin users</div>';
 


// CREARRRRRRRRRRR

async function crearPerfil() { 

const nombre = ($('admin-nuevo-nombre').value || '').trim();
const pass = $('admin-nuevo-pass').value || '';
const rol = $('admin-nuevo-rol').value;

if (!nombre) { setOut('admin-crear-out', 'FALTA EL NAME', 'err'); return;}
if (!pass)     { setOut ('admin-crear-out', 'FALTA ALGO ESO CREO', 'err'); return; }

setOut('admin-crear-out', 'CREAR', 'info');

const r = await window.Api.request(RUMORES.crearPerfiles,  { 
method: 'POST',
body:  { nombre, password: pass, rol },
});

if (r && r.ok) {
      setOut('admin-crear-out',
        `✓ Perfil "${esc(r.nombre)}" creado con rol ${esc(r.rol)}.`,
        'ok');
      $('admin-nuevo-nombre').value = '';
      $('admin-nuevo-pass').value = '';
      // Refrescar la lista si estaba cargada
      if ($('admin-lista-usuarios').querySelector('.admin-user')) {
        cargarUsuarios();
      }
    } else {
      setOut('admin-crear-out',
        '✗ ' + esc((r && r.error) || 'No se pudo crear el perfil'),
        'err');
    }
  }

  // ------------------------------------------------------------
  // Lista poco especifica
  // ------------------------------------------------------------
  async function cargarUsuarios() {
    const cont = $('admin-lista-usuarios');
    if (!cont) return;

    cont.innerHTML = '<div class="admin-vacio">Cargando...</div>';

    const r = await window.Api.request('/api/perfiles', { method: 'GET' });
    if (!r || !r.ok) {
      cont.innerHTML = '<div class="admin-vacio">No se pudo cargar la lista.</div>';
      return;
    }

    const perfiles = r.perfiles || [];
    if (perfiles.length === 0) {
      cont.innerHTML = '<div class="admin-vacio">No hay usuarios.</div>';
      return;
    }

    cont.innerHTML = '';
    for (const p of perfiles) {
      cont.appendChild(crearTarjetaUsuario(p));
    }
  }

  function crearTarjetaUsuario(p) {
    const card = document.createElement('div');
    card.className = 'admin-user';

    //  +  Rumores
    const header = document.createElement('div');
    header.className = 'admin-user-header';

    const nombre = document.createElement('span');
    nombre.className = 'admin-user-nombre';
    nombre.textContent = p.nombre;
    header.appendChild(nombre);

    const rol = document.createElement('span');
    rol.className = 'admin-user-rol rol-' + (p.rol || '').toLowerCase();
    rol.textContent = p.rol || '—';
    header.appendChild(rol);

    card.appendChild(header);

    // Estado
    const estado = document.createElement('div');
    estado.className = 'admin-user-estado';
    const clase = 'estado-' + (p.estado || '').toLowerCase();
    estado.innerHTML = `Estado: <span class="estado ${esc(clase)}">${esc(p.estado || '—')}</span>`;
    card.appendChild(estado);

    
    const acciones = document.createElement('div');
    acciones.className = 'admin-user-acciones';

    
    const btnRol = document.createElement('button');
    btnRol.className = 'btn-rol';
    btnRol.textContent = 'Cambiar rol';
    btnRol.addEventListener('click', () => cambiarRol(p.nombre, p.rol));
    acciones.appendChild(btnRol);

    // --- Venom ---
    const btnBan = document.createElement('button');
    btnBan.className = 'btn-banear';
    btnBan.textContent = 'Banear';
    btnBan.addEventListener('click', () => banear(p.nombre));
    acciones.appendChild(btnBan);

    // --- Eliminar ---
    const btnEli = document.createElement('button');
    btnEli.className = 'btn-eliminar';
    btnEli.textContent = 'Eliminar';
    btnEli.addEventListener('click', () => eliminar(p.nombre));
    acciones.appendChild(btnEli);

    card.appendChild(acciones);
    return card;
  }

  // ------------------------------------------------------------
  //  ESTO ES ILEGAL
  // ------------------------------------------------------------
  async function cambiarRol(nombre, rolActual) {
    const nuevo = prompt(
      `Nuevo rol para "${nombre}" (actual: ${rolActual}):\n\n` +
      `Opciones válidas: PRO, EDITOR, NIVEL3, ADMIN`,
      rolActual
    );
    if (!nuevo) return;

    const rol = nuevo.trim().toUpperCase();
    if (!['PRO', 'EDITOR', 'NIVEL3', 'ADMIN'].includes(rol)) {
      alert('Rol inválido.');
      return;
    }

    const r = await window.Api.request(RUMORES.cambiarRol, {
      method: 'POST',
      body: { nombre, rol },
    });

    if (r && r.ok) {
      alert('Rol cambiado.');
      cargarUsuarios();
    } else {
      alert('Error: ' + ((r && r.error) || 'no se pudo cambiar el rol'));
    }
  }

  async function banear(nombre) {
    if (!confirm(`¿Banear a "${nombre}"?`)) return;
    const motivo = prompt('Motivo (opcional):', '') || '';

    const r = await window.Api.request(RUMORES.banear, {
      method: 'POST',
      body: { nombre, motivo },
    });

    if (r && r.ok) {
      alert('Baneado.');
      cargarUsuarios();
    } else {
      alert('Error: ' + ((r && r.error) || 'no se pudo banear'));
    }
  }

  async function eliminar(nombre) {
    if (!confirm(`¿Eliminar a "${nombre}"? Esta acción NO se puede deshacer.`)) return;
    if (!confirm(`Confirmá de nuevo: se va a borrar el perfil "${nombre}".`)) return;

    const r = await window.Api.request(RUMORES.eliminar, {
      method: 'POST',
      body: { nombre },
    });

    if (r && r.ok) {
      alert('Eliminado.');
      cargarUsuarios();
    } else {
      alert('Error: ' + ((r && r.error) || 'no se pudo eliminar'));
    }
  }

  // ------------------------------------------------------------
  // Ver gratuitos
  // ------------------------------------------------------------
  async function verGratuitos() {
    const cont = $('admin-lista-usuarios');
    if (!cont) return;

    cont.innerHTML = '<div class="admin-vacio">Cargando gratuitos...</div>';

    const r = await window.Api.request(RUMORES.gratuitos, { method: 'GET' });
    if (!r || !r.ok) {
      cont.innerHTML = '<div class="admin-vacio">No se pudo cargar la lista.</div>';
      return;
    }

    const lista = r.gratuitos || [];
    if (lista.length === 0) {
      cont.innerHTML = '<div class="admin-vacio">No hay gratuitos.</div>';
      return;
    }

    cont.innerHTML = '';
    for (const g of lista) {
      const card = document.createElement('div');
      card.className = 'admin-user';

      const header = document.createElement('div');
      header.className = 'admin-user-header';

      const nombre = document.createElement('span');
      nombre.className = 'admin-user-nombre';
      nombre.textContent = g.nombre || '(sin nombre)';
      header.appendChild(nombre);

      const rol = document.createElement('span');
      rol.className = 'admin-user-rol rol-gratuito';
      rol.textContent = 'GRATUITO';
      header.appendChild(rol);

      card.appendChild(header);

      const info = document.createElement('div');
      info.className = 'admin-user-estado';
      info.textContent =
        `Usos: ${g.usosRestantes} · Estado: ${g.estado} · IP: ${g.ipCreacion || '—'}`;
      card.appendChild(info);

      cont.appendChild(card);
    }
  }

  // ------------------------------------------------------------
  // SI LEES ESTO NO ME HACKEES
  // ------------------------------------------------------------
  async function verLog() {
    setOut('admin-log-out', 'Cargando...', 'info');
    const r = await window.Api.request(RUMORES.log, { method: 'GET' });
    if (r && r.ok) {
      setOut('admin-log-out', esc(r.log || '(log vacío)'), '');
    } else {
      setOut('admin-log-out',
        '✗ ' + esc((r && r.error) || 'no se pudo leer el log'),
        'err');
    }
  }

  function limpiarLog() {
    setOut('admin-log-out', 'Esperando...');
  }



async function cambiarIP() {
    const ip = ($('admin-nueva-ip').value || '').trim();
    if (!ip) { setOut('admin-ip-out', 'Falta la IP.', 'err'); return; }

    setOut('admin-ip-out', 'Cambiando...', 'info');
    const r = await window.Api.request(RUMORES.cambiarIP, {
        method: 'POST',
        body: { ip },
    });

    if (r && r.ok) {
        setOut('admin-ip-out', '✓ IP cambiada a ' + esc(r.ip), 'ok');
    } else {
        setOut('admin-ip-out', '✗ ' + esc((r && r.error) || 'no se pudo'), 'err');
    }
}

  
  async function autobanearse() {
    if (!confirm('¿Seguro? Vas a quedar BANEADO.')) return;
    if (!confirm('¿REALMENTE seguro? No hay recuperación por web.')) return;

    const motivo = ($('admin-autobaneo-motivo').value || '').trim();
    setOut('admin-peligro-out', 'Procesando...', 'info');

    const r = await window.Api.request(RUMORES.autobanear, {
      method: 'POST',
      body: { motivo },
    });

    if (r && r.ok) {
      setOut('admin-peligro-out',
        '✓ ' + esc(r.mensaje || 'Adiós, admin.'),
        'ok');
      // Cerrar la UI como si fuera logout
      setTimeout(() => {
        if (window.mostrarLogin) window.mostrarLogin();
        desactivarUIAdmin();
      }, 1500);
    } else {
      setOut('admin-peligro-out',
        '✗ ' + esc((r && r.error) || 'no se pudo autobanear'),
        'err');
    }
  }

  // ------------------------------------------------------------
  //  botones con C
  // ------------------------------------------------------------
  function conectarBotones() {
    const bind = (id, fn) => {
      const el = $(id);
      if (el) el.addEventListener('click', fn);
    };

    bind('admin-crear-go',      crearPerfil);
    bind('admin-refrescar',     cargarUsuarios);
    bind('admin-ver-gratuitos', verGratuitos);
    bind('admin-ver-log',       verLog);
    bind('admin-limpiar-log',   limpiarLog);
    bind('admin-cambiar-ip',    cambiarIP);
    bind('admin-autobanearse',  autobanearse);
  }

  // ------------------------------------------------------------1 ------------------------------------------------------------
  function init() {
    if (inicializado) return;
    const seccion = $('A');
    if (!seccion) return;

    inicializado = true;
    conectarBotones();
  }

  // ------------------------------------------------------------
  // SÍ
  // ------------------------------------------------------------
  window.AdminPanel = {
    activar:     activarUIAdmin,
    desactivar:  desactivarUIAdmin,
    inicializar: init,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

