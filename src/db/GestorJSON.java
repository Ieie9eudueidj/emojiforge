// ============================================================
// GestorJSON.java
// Corazón del sistema: lee y escribe todos los JSONs del disco.
// Aplica las reglas de negocio:
//   - Solo un admin.
//   - Límite de 2000 perfiles gratis activos.
//   - Rate limiting de registro (100/min por IP, 200/min global).
//   - Confirmación de rol + ubicación al escribir.
//   - Checksum de índice.
//   - Fallback a indice.json.bak.
// Ahora también cifra/descifra perfiles con Cifrado.java.
// La clave interna se deriva del ID + clave maestra: no se guarda.
// Thread-safe con synchronized.
// Sin dependencias externas.
// ============================================================
package db;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class GestorJSON {

    // ============================================================
    // Rutas base
    // ============================================================
    private static final Path DATA_DIR       = Paths.get("server", "data");
    private static final Path PERFILES_DIR   = DATA_DIR.resolve("perfiles");
    private static final Path GRATUITOS_DIR  = DATA_DIR.resolve("gratuitos");
    private static final Path INDICE_PATH    = DATA_DIR.resolve("indice.json");
    private static final Path INDICE_BAK     = DATA_DIR.resolve("indice.json.bak");
    private static final Path BANEADOS_PATH  = DATA_DIR.resolve("baneados.json");
    private static final Path BANEADOS_BAK   = DATA_DIR.resolve("baneados.json.bak");
private static final Path NOMBRES_GRATUITOS_PATH = DATA_DIR.resolve("nombres_gratuitos.json");
private static final Path NOMBRES_GRATUITOS_BAK  = DATA_DIR.resolve("nombres_gratuitos.json.bak");
    // ============================================================
    // Límites de negocio
    // ============================================================
    private static final int LIMITE_ROL0_ACTIVOS_DEFECTO = 2000;
    private static final int REGISTROS_POR_IP_POR_MINUTO = 100;
    private static final int REGISTROS_GLOBALES_POR_MINUTO = 200;
    private static final long VENTANA_RATE_LIMIT_MS = 60_000L;
    private static final int TAMANIO_MAX_JSON = 400 * 1024;

    // ============================================================
    // Estado interno
    // ============================================================
    private  Modelo.Indice indice;
    private List<Modelo.Baneado> baneados;
        private final Map<String, String> nombresGratuitos = new HashMap<>();
    private final Map<String, List<Long>> registrosPorIP = new HashMap<>();
    private final List<Long> registrosGlobales = new ArrayList<>();

    // ============================================================
    // Constructor
    // ============================================================
    public GestorJSON() {
        asegurarCarpetas();
    }

    // ============================================================
    // Arranque
    // ============================================================
    public synchronized void arrancar() {
    cargarNombresGratuitos();
    this.baneados = cargarBaneadosDesdeDisco();
        try {
            this.indice = cargarIndiceDesdeDisco(INDICE_PATH);
            return;
        } catch (Exception e) {
            System.err.println("[gestor] índice principal no sirve: " + e.getMessage());
        }

        if (Files.exists(INDICE_BAK)) {
            try {
                this.indice = cargarIndiceDesdeDisco(INDICE_BAK);
                System.err.println("[gestor] recuperado desde indice.json.bak");
                escribirIndiceEnDisco(this.indice, INDICE_PATH);
                return;
            } catch (Exception e) {
                System.err.println("[gestor] backup tampoco sirve: " + e.getMessage());
            }
        }

        throw new Json.JsonException(
            "No se pudo cargar el índice ni su backup. " +
            "Arreglá indice.json o borralo para arrancar con uno vacío."
        );
    }

    public synchronized void arrancarIgnorandoIndice() {
    try {
        if (Files.exists(INDICE_PATH)) {
            Files.move(INDICE_PATH, INDICE_BAK, StandardCopyOption.REPLACE_EXISTING);
        }
    } catch (IOException e) {
        System.err.println("[gestor] no se pudo respaldar índice: " + e.getMessage());
    }
    this.indice = new  Modelo.Indice();
    this.baneados = cargarBaneadosDesdeDisco();
    nombresGratuitos.clear();
    guardarNombresGratuitos();
    guardarIndice(this.indice);
}

    // ============================================================
    // Índice: lectura / escritura
    // ============================================================
    private  Modelo.Indice cargarIndiceDesdeDisco(Path ruta) {
        if (!Files.exists(ruta)) {
            throw new Json.JsonException("No existe el archivo: " + ruta);
        }
        try {
            byte[] bytes = Files.readAllBytes(ruta);
            if (bytes.length > TAMANIO_MAX_JSON) {
                throw new Json.JsonException("Índice mayor a 400 KB: " + bytes.length);
            }
            String texto = new String(bytes, StandardCharsets.UTF_8);
            Json j = Json.parse(texto);

            Json copia = Json.parse(texto);
            String checksumGuardado = copia.get("checksum") != null
                ? copia.get("checksum").asString()
                : null;
            copia.quitar("checksum");
            String checksumCalculado = calcularChecksum(copia);

            if (checksumGuardado == null || !checksumGuardado.equals(checksumCalculado)) {
                throw new Json.JsonException("Checksum del índice no coincide");
            }

            return Modelo.Indice.desdeJson(copia);
        } catch (IOException e) {
            throw new Json.JsonException("Error leyendo índice: " + e.getMessage());
        }
    }

    private void escribirIndiceEnDisco(Modelo.Indice idx, Path ruta) {
        Json j = idx.aJson();
        j.quitar("checksum");
        String checksum = calcularChecksum(j);
        j.set("checksum", checksum);

        String texto = j.toString(2);
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);

        if (bytes.length > TAMANIO_MAX_JSON) {
            throw new Json.JsonException("Índice excede 400 KB: " + bytes.length);
        }

        try {
            Files.write(ruta, bytes);
        } catch (IOException e) {
            throw new Json.JsonException("Error escribiendo índice: " + e.getMessage());
        }
    }

    public synchronized void guardarIndice(Modelo.Indice idx) {
        if (idx == null) throw new Json.JsonException("Índice nulo");
        if (Files.exists(INDICE_PATH)) {
            try {
                Files.copy(INDICE_PATH, INDICE_BAK, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                System.err.println("[gestor] no se pudo respaldar índice: " + e.getMessage());
            }
        }
        escribirIndiceEnDisco(idx, INDICE_PATH);
        this.indice = idx;
    }

    public synchronized Modelo.Indice indice() {
        return indice;
    }

    // ============================================================
    // Checksum
    // ============================================================
    public static String calcularChecksum(Json j) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = j.toString().getBytes(StandardCharsets.UTF_8);
            byte[] hash = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new Json.JsonException("SHA-256 no disponible");
        }
    }

    // ============================================================
    // Confirmación de rol + ubicación
    // ============================================================
    private void confirmarRolYUbicacion(Modelo.Perfil p) {
        if (p == null) throw new Json.JsonException("Perfil nulo");
        if (p.rol() == null)
            throw new Json.JsonException("Perfil sin rol");
        if (p.rol() == Modelo.Rol.GRATUITO)
            throw new Json.JsonException("Perfil con rol GRATUITO no puede guardarse como pro");
        if (p.id() == null || p.id().isBlank())
            throw new Json.JsonException("Perfil sin ID");
        if (p.nombre() == null || p.nombre().isBlank())
            throw new Json.JsonException("Perfil sin nombre");
        if (p.hashPassword() == null || p.hashPassword().isBlank())
            throw new Json.JsonException("Perfil sin hash de contraseña");
        if (p.saltPassword() == null || p.saltPassword().isBlank())
            throw new Json.JsonException("Perfil sin salt de contraseña");
    }

    private void confirmarRolYUbicacion(Modelo.PerfilGratuito p) {
        if (p == null) throw new Json.JsonException("Perfil gratis nulo");
        if (p.id() == null || p.id().isBlank())
            throw new Json.JsonException("Perfil gratis sin ID");
        if (p.nombre() == null || p.nombre().isBlank())
            throw new Json.JsonException("Perfil gratis sin nombre");
        if (p.hashPassword() == null || p.hashPassword().isBlank())
            throw new Json.JsonException("Perfil gratis sin hash de contraseña");
        if (p.saltPassword() == null || p.saltPassword().isBlank())
            throw new Json.JsonException("Perfil gratis sin salt de contraseña");
        if (p.usosRestantes() < 0)
            throw new Json.JsonException("Perfil gratis con usos negativos");
        if (p.usosRestantes() > Modelo.PerfilGratuito.USOS_INICIALES)
            throw new Json.JsonException("Perfil gratis con usos mayores al inicial");
    }

    // ============================================================
    // Perfiles pro (unificado: cualquier rol 1+)
    // ============================================================
    public synchronized Modelo.Perfil crearPerfilPro(
            String nombre, Modelo.Rol rol,
            String hash, String salt, String ip) {
        if (rol == null || rol == Modelo.Rol.GRATUITO)
            throw new Json.JsonException("Rol inválido para perfil pro");
        if (nombre == null || nombre.isBlank())
            throw new Json.JsonException("Nombre vacío");
        if (indice.contiene(nombre))
            throw new Json.JsonException("Nombre ya en uso");
        if (estaBaneado(null, ip))
            throw new Json.JsonException("IP baneada");
        if (rol == Modelo.Rol.ADMIN && existeAdmin())
            throw new Json.JsonException("Ya existe un administrador");

        Modelo.Perfil p = Modelo.Perfil.nuevo(nombre, rol, hash, salt, ip);
        confirmarRolYUbicacion(p);

        String claveInterna = Cifrado.derivarClaveInterna(p.id());
        Path ruta = PERFILES_DIR.resolve(p.id() + ".json");
        escribirPerfilCifrado(p.aJson(), ruta, claveInterna, p.id());

        Modelo.EntradaIndice e = new Modelo.EntradaIndice(
            p.nombre(), p.rol(), "perfiles/" + p.id() + ".json", p.estado(),
            claveInterna
        );
        indice.agregar(e);
        guardarIndice(indice);
        return p;
    }

    public synchronized Modelo.Perfil leerPerfil(String nombre) {
        Modelo.EntradaIndice e = indice.buscar(nombre);
        if (e == null) return null;
        Path ruta = DATA_DIR.resolve(e.ruta());
        if (!Files.exists(ruta)) return null;
        try {
            String id = extraerIdDeRuta(e.ruta());
            String claveInterna = Cifrado.derivarClaveInterna(id);
            byte[] cifrado = Files.readAllBytes(ruta);
            byte[] plano = Cifrado.descifrarPerfil(cifrado, claveInterna, id);
            Json j = Json.parse(new String(plano, StandardCharsets.UTF_8));
            Modelo.Perfil p = Modelo.Perfil.desdeJson(j);
            confirmarRolYUbicacion(p);
            return p;
        } catch (IOException ex) {
            throw new Json.JsonException("Error leyendo perfil: " + ex.getMessage());
        }
    }

    public synchronized Modelo.Perfil leerPerfilPorId(String id) {
    if (id == null || id.isBlank()) return null;
    for (Modelo.EntradaIndice e : indice.entradas()) {
        Modelo.Perfil p = leerPerfil(e.nombre());
        if (p != null && p.id().equals(id)) return p;
    }
    return null;
}
    
    

 public synchronized void cambiarIP(String nombre, String nuevaIP){
Modelo.Perfil p = leerPerfil(nombre);
if (p == null) throw new Json.JsonException("Perfil no existe");
p.setIP(nuevaIP);
actualizarPerfil(p);

}

    public synchronized void actualizarPerfil(Modelo.Perfil p) {
        confirmarRolYUbicacion(p);
        String claveInterna = Cifrado.derivarClaveInterna(p.id());
        Path ruta = PERFILES_DIR.resolve(p.id() + ".json");
        escribirPerfilCifrado(p.aJson(), ruta, claveInterna, p.id());

        indice.quitar(p.nombre());
        indice.agregar(new Modelo.EntradaIndice(
            p.nombre(), p.rol(), "perfiles/" + p.id() + ".json", p.estado(),
            claveInterna
        ));
        guardarIndice(indice);
    }

    public synchronized void eliminarPerfil(String nombre) {
        Modelo.EntradaIndice e = indice.buscar(nombre);
        if (e == null) return;
        Path ruta = DATA_DIR.resolve(e.ruta());
        try {
            if (!Files.deleteIfExists(ruta)) {
                System.err.println("[gestor] perfil no estaba en disco: " + ruta);
            }
        } catch (IOException ex) {
            System.err.println("[gestor] no se pudo borrar perfil: " + ex.getMessage());
        }
        indice.quitar(nombre);
        guardarIndice(indice);
    }

    // ============================================================
    // Perfiles gratis (rol 0)
    // El archivo se llama "<id>.json". La clave interna NO se
    // guarda en ningún lado: se deriva del ID + clave maestra.
    // ============================================================
    public synchronized Modelo.PerfilGratuito crearPerfilGratuito(
            String nombre, String hash, String salt, String ip) {
        if (nombre == null || nombre.isBlank())
            throw new Json.JsonException("Nombre vacío");

        if (estaBaneado(null, ip))
            throw new Json.JsonException("IP baneada");

        if (!puedeRegistrarse(ip))
            throw new Json.JsonException("Demasiados registros recientes");

        if (contarGratuitosActivos() >= indice.limiteRol0())
            throw new Json.JsonException("Límite de perfiles gratuitos alcanzado");

        if (indice.contiene(nombre)) {
            throw new Json.JsonException("Nombre no disponible");
        }

        Modelo.PerfilGratuito p = Modelo.PerfilGratuito.nuevo(nombre, hash, salt, ip);
        confirmarRolYUbicacion(p);

        String claveInterna = Cifrado.derivarClaveInterna(p.id());
        Path ruta = GRATUITOS_DIR.resolve(nombreArchivoGratuito(p.id()));
escribirPerfilCifrado(p.aJson(), ruta, claveInterna, p.id());

agregarNombreGratuito(p.nombre(), p.id());
registrarIntentoDeRegistro(ip);
                return p;
                  }

    public synchronized Modelo.PerfilGratuito leerPerfilGratuito(String id) {
        if (id == null || id.isBlank()) return null;
        Path ruta = GRATUITOS_DIR.resolve(nombreArchivoGratuito(id));
        if (!Files.exists(ruta)) return null;
        try {
            String claveInterna = Cifrado.derivarClaveInterna(id);
            byte[] cifrado = Files.readAllBytes(ruta);
            byte[] plano = Cifrado.descifrarPerfil(cifrado, claveInterna, id);
            Json j = Json.parse(new String(plano, StandardCharsets.UTF_8));
            Modelo.PerfilGratuito p = Modelo.PerfilGratuito.desdeJson(j);
            confirmarRolYUbicacion(p);
            return p;
        } catch (IOException ex) {
            throw new Json.JsonException("Error leyendo perfil gratis: " + ex.getMessage());
        }
    }

    public synchronized void actualizarPerfilGratuito(Modelo.PerfilGratuito p) {
        confirmarRolYUbicacion(p);
        String claveInterna = Cifrado.derivarClaveInterna(p.id());
        Path ruta = GRATUITOS_DIR.resolve(nombreArchivoGratuito(p.id()));
        escribirPerfilCifrado(p.aJson(), ruta, claveInterna, p.id());
    }


  public synchronized void eliminarPerfilGratuito(String id) {
    if (id == null || id.isBlank()) return;

    // Buscar el nombre para quitarlo del mapa
    String nombreEncontrado = null;
    for (Map.Entry<String, String> e : nombresGratuitos.entrySet()) {
        if (e.getValue().equals(id)) { nombreEncontrado = e.getKey(); break; }
    }
    if (nombreEncontrado != null) quitarNombreGratuito(nombreEncontrado);

    Path ruta = GRATUITOS_DIR.resolve(nombreArchivoGratuito(id));
    try {
        Files.deleteIfExists(ruta);
    } catch (IOException ex) {
        System.err.println("[gestor] no se pudo borrar perfil gratis: " + ex.getMessage());
    }
}

    // ============================================================
    // Escritura cifrada de perfiles
    // ============================================================
    private void escribirPerfilCifrado(Json j, Path ruta, String claveInterna, String id) {
        String texto = j.toString(2);
        byte[] plano = texto.getBytes(StandardCharsets.UTF_8);
        byte[] cifrado = Cifrado.cifrarPerfil(plano, claveInterna, id);
        if (cifrado.length > TAMANIO_MAX_JSON) {
            throw new Json.JsonException("JSON cifrado excede 400 KB: " + cifrado.length);
        }
        try {
            Files.write(ruta, cifrado);
        } catch (IOException e) {
            throw new Json.JsonException("Error escribiendo perfil cifrado: " + e.getMessage());
        }
    }

    // ============================================================
    // Contadores y listados de gratuitos
    // ============================================================
    public synchronized int contarGratuitosActivos() {
        if (!Files.exists(GRATUITOS_DIR)) return 0;
        int contador = 0;
        try {
            List<Path> archivos = Files.list(GRATUITOS_DIR).toList();
            for (Path a : archivos) {
                if (!a.toString().endsWith(".json")) continue;
                try {
                    String id = parsearIdGratuito(a.getFileName().toString());
                    if (id == null) continue;

                    String claveInterna = Cifrado.derivarClaveInterna(id);
                    byte[] cifrado = Files.readAllBytes(a);
                    byte[] plano = Cifrado.descifrarPerfil(cifrado, claveInterna, id);
                    Json j = Json.parse(new String(plano, StandardCharsets.UTF_8));
                    String estado = j.get("estado").asString();
                    long usos = j.get("usosRestantes").asLong();
                    if ("ACTIVO".equals(estado) && usos > 0) contador++;
                } catch (Exception e) {
                    // Ignorar archivos corruptos
                }
            }
        } catch (IOException e) {
            System.err.println("[gestor] no se pudo listar gratuitos: " + e.getMessage());
        }
        return contador;
    }

    // ============================================================
    // Admin
    // ============================================================
    public synchronized boolean existeAdmin() {
        for (Modelo.EntradaIndice e : indice.entradas()) {
            if (e.rol() == Modelo.Rol.ADMIN) return true;
        }
        return false;
    }

    public synchronized Modelo.Perfil crearAdminInicial(
            String nombre, String hash, String salt) {
        if (existeAdmin())
            throw new Json.JsonException("Ya existe un administrador");
        if (nombre == null || nombre.isBlank())
            nombre = Modelo.AdminPorDefecto.NOMBRE_DEFECTO;
        if (indice.contiene(nombre))
            throw new Json.JsonException("Nombre ya en uso por otro perfil");

        return crearPerfilPro(nombre, Modelo.Rol.ADMIN, hash, salt, "127.0.0.1");
    }

    // ============================================================
    // Baneados
    // ============================================================
    private List<Modelo.Baneado> cargarBaneadosDesdeDisco() {
        List<Modelo.Baneado> lista = new ArrayList<>();
        if (!Files.exists(BANEADOS_PATH)) return lista;
        try {
            String texto = new String(Files.readAllBytes(BANEADOS_PATH), StandardCharsets.UTF_8);
            Json j = Json.parse(texto);
            Json arr = j.get("baneados");
            if (arr != null && arr.esArray()) {
                for (Json e : arr.elementos()) {
                    lista.add(Modelo.Baneado.desdeJson(e));
                }
            }
        } catch (Exception e) {
            System.err.println("[gestor] error leyendo baneados: " + e.getMessage());
        }
        return lista;
    }

    public synchronized void guardarBaneados(List<Modelo.Baneado> lista) {
        this.baneados = new ArrayList<>(lista);
        Json j = Json.object();
        Json arr = Json.array();
        for (Modelo.Baneado b : lista) arr.add(b.aJson());
        j.set("baneados", arr);

        j.quitar("checksum");
        String checksum = calcularChecksum(j);
        j.set("checksum", checksum);

        String texto = j.toString(2);
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        try {
            if (Files.exists(BANEADOS_PATH)) {
                Files.copy(BANEADOS_PATH, BANEADOS_BAK, StandardCopyOption.REPLACE_EXISTING);
            }
            Files.write(BANEADOS_PATH, bytes);
        } catch (IOException e) {
            throw new Json.JsonException("Error escribiendo baneados: " + e.getMessage());
        }
    }

    public synchronized void agregarBaneado(Modelo.Baneado b) {
        for (Modelo.Baneado x : baneados) {
            if (x.id().equals(b.id()) || (x.ip() != null && x.ip().equals(b.ip()))) {
                return;
            }
        }
        baneados.add(b);
        guardarBaneados(baneados);
    }

    public synchronized boolean estaBaneado(String id, String ip) {
        for (Modelo.Baneado b : baneados) {
            if (id != null && b.id() != null && b.id().equals(id)) return true;
            if (ip != null && b.ip() != null && b.ip().equals(ip)) return true;
        }
        return false;
    }

    public synchronized List<Modelo.Baneado> baneados() {
        return new ArrayList<>(baneados);
    }

    // ============================================================
    // Rate limiting de registro
    // ============================================================
    public synchronized boolean puedeRegistrarse(String ip) {
        long ahora = System.currentTimeMillis();
        limpiarVentanas(ahora);
        if (registrosGlobales.size() >= REGISTROS_GLOBALES_POR_MINUTO) return false;
        if (ip != null) {
            List<Long> veces = registrosPorIP.get(ip);
            if (veces != null && veces.size() >= REGISTROS_POR_IP_POR_MINUTO) return false;
        }
        return true;
    }

    private void registrarIntentoDeRegistro(String ip) {
        long ahora = System.currentTimeMillis();
        registrosGlobales.add(ahora);
        if (ip != null) {
            registrosPorIP.computeIfAbsent(ip, k -> new ArrayList<>()).add(ahora);
        }
    }

    private void limpiarVentanas(long ahora) {
        long corte = ahora - VENTANA_RATE_LIMIT_MS;
        registrosGlobales.removeIf(t -> t < corte);
        for (List<Long> lista : registrosPorIP.values()) {
            lista.removeIf(t -> t < corte);
        }
        registrosPorIP.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    // ============================================================
    // Utilidades
    // ============================================================
    public synchronized List<Modelo.EntradaIndice> listarTodos() {
        return new ArrayList<>(indice.entradas());
    }

    public synchronized List<Modelo.PerfilGratuito> listarGratuitos() {
        List<Modelo.PerfilGratuito> lista = new ArrayList<>();
        if (!Files.exists(GRATUITOS_DIR)) return lista;
        try {
            List<Path> archivos = Files.list(GRATUITOS_DIR).toList();
            for (Path a : archivos) {
                if (!a.toString().endsWith(".json")) continue;
                try {
                    String id = parsearIdGratuito(a.getFileName().toString());
                    if (id == null) continue;

                    String claveInterna = Cifrado.derivarClaveInterna(id);
                    byte[] cifrado = Files.readAllBytes(a);
                    byte[] plano = Cifrado.descifrarPerfil(cifrado, claveInterna, id);
                    Json j = Json.parse(new String(plano, StandardCharsets.UTF_8));
                    lista.add(Modelo.PerfilGratuito.desdeJson(j));
                } catch (Exception e) {
                    // Ignorar archivos corruptos
                }
            }
        } catch (IOException e) {
            System.err.println("[gestor] error listando gratuitos: " + e.getMessage());
        }
        return lista;
    }

    public Path rutaPerfil(String id) {
        return PERFILES_DIR.resolve(id + ".json");
    }

    public Path rutaGratuito(String id) {
        if (id == null || id.isBlank()) return null;
        return GRATUITOS_DIR.resolve(nombreArchivoGratuito(id));
    }

    // ============================================================
    // Helpers para perfiles gratuitos
    // ============================================================
    private static String nombreArchivoGratuito(String id) {
        return id + ".json";
    }

    private static String parsearIdGratuito(String nombre) {
        if (nombre == null || !nombre.endsWith(".json")) return null;
        String id = nombre.substring(0, nombre.length() - 5);
        if (id.isBlank()) return null;
        return id;
    }

    private static String extraerIdDeRuta(String ruta) {
        if (ruta == null) return null;
        int slash = ruta.lastIndexOf('/');
        String archivo = slash >= 0 ? ruta.substring(slash + 1) : ruta;
        if (archivo.endsWith(".json")) archivo = archivo.substring(0, archivo.length() - 5);
        return archivo;
    }

                // ============================================================
// nombres_gratuitos.json
// Mapa nombre -> id para perfiles rol 0.
// Solo guarda la relación, no datos sensibles.
// ============================================================
public synchronized String buscarIdGratuitoPorNombre(String nombre) {
    if (nombre == null) return null;
    return nombresGratuitos.get(nombre);
}

public synchronized boolean existeNombreGratuito(String nombre) {
    return nombre != null && nombresGratuitos.containsKey(nombre);
}

private void agregarNombreGratuito(String nombre, String id) {
    nombresGratuitos.put(nombre, id);
    guardarNombresGratuitos();
}

private void quitarNombreGratuito(String nombre) {
    if (nombresGratuitos.remove(nombre) != null) {
        guardarNombresGratuitos();
    }
}

private void cargarNombresGratuitos() {
    nombresGratuitos.clear();
    if (!Files.exists(NOMBRES_GRATUITOS_PATH)) return;
    try {
        String texto = new String(
            Files.readAllBytes(NOMBRES_GRATUITOS_PATH), StandardCharsets.UTF_8);
        Json j = Json.parse(texto);

        Json copia = Json.parse(texto);
        String checksumGuardado = copia.get("checksum") != null
            ? copia.get("checksum").asString() : null;
        copia.quitar("checksum");
        String checksumCalculado = calcularChecksum(copia);
        if (checksumGuardado == null || !checksumGuardado.equals(checksumCalculado)) {
            System.err.println("[gestor] checksum de nombres_gratuitos no coincide. Ignorando.");
            return;
        }

        Json mapa = j.get("nombres");
        if (mapa != null && mapa.esObjeto()) {
            for (String clave : mapa.claves()) {
                Json v = mapa.get(clave);
                if (v != null && v.esString()) {
                    nombresGratuitos.put(clave, v.asString());
                }
            }
        }
    } catch (Exception e) {
        System.err.println("[gestor] error leyendo nombres_gratuitos: " + e.getMessage());
    }
}

private void guardarNombresGratuitos() {
    Json j = Json.object();
    j.set("version", 1);
    Json mapa = Json.object();
    for (Map.Entry<String, String> e : nombresGratuitos.entrySet()) {
        mapa.set(e.getKey(), e.getValue());
    }
    j.set("nombres", mapa);

    j.quitar("checksum");
    String checksum = calcularChecksum(j);
    j.set("checksum", checksum);

    String texto = j.toString(2);
    byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > TAMANIO_MAX_JSON) {
        throw new Json.JsonException("nombres_gratuitos excede 400 KB");
    }
    try {
        if (Files.exists(NOMBRES_GRATUITOS_PATH)) {
            Files.copy(NOMBRES_GRATUITOS_PATH, NOMBRES_GRATUITOS_BAK,
                StandardCopyOption.REPLACE_EXISTING);
        }
        Files.write(NOMBRES_GRATUITOS_PATH, bytes);
    } catch (IOException e) {
        throw new Json.JsonException("Error guardando nombres_gratuitos: " + e.getMessage());
    }
}
                
                
    // ============================================================
    // Setup de carpetas
    // ============================================================
    private void asegurarCarpetas() {
        try {
            Files.createDirectories(DATA_DIR);
            Files.createDirectories(PERFILES_DIR);
            Files.createDirectories(GRATUITOS_DIR);
        } catch (IOException e) {
            throw new Json.JsonException(
                "No se pudieron crear las carpetas de datos: " + e.getMessage()
            );
        }
    }
}