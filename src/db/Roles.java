// ============================================================
// Roles.java
// Validación de permisos por rol.
//
// NO redefine la jerarquía (eso vive en Modelo.Rol).
// Solo decide si una Sesion puede hacer una acción, y si puede
// hacerla sobre un objetivo concreto. Loguea los intentos no
// autorizados en logs/seguridad.log.
//
// También incluye el método AUTOBANEO, que le permite al admin
// banearse a sí mismo. Sí, en serio. Está ahí abajo, bien grande.
// ============================================================
package db;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class Roles {

    // ============================================================
    // Log de seguridad
    // ============================================================
    private static final Path LOG_SEGURIDAD = Paths.get("logs", "seguridad.log");
    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ============================================================
    // Catálogo de acciones
    // Cada acción tiene un rol mínimo y reglas de objetivo.
    // ============================================================
    public enum Accion {
        // Acciones generales
        USAR_HERRAMIENTA          (Modelo.Rol.GRATUITO),
        VER_SU_PROPIO_PERFIL      (Modelo.Rol.GRATUITO),
        CAMBIAR_SU_CONTRASENA     (Modelo.Rol.GRATUITO),
        CERRAR_SESION_PROPIA      (Modelo.Rol.GRATUITO),
        EDITAR_SU_PROPIO_PERFIL   (Modelo.Rol.NIVEL3),

        // Acciones sobre otros perfiles
        VER_LISTA_PERFILES        (Modelo.Rol.EDITOR),
        VER_PERFIL_AJENO          (Modelo.Rol.EDITOR),
        EDITAR_PERFIL_AJENO       (Modelo.Rol.ADMIN),
        CAMBIAR_ROL               (Modelo.Rol.ADMIN),
        BANEAR                    (Modelo.Rol.ADMIN),
        ELIMINAR                  (Modelo.Rol.ADMIN),
        CREAR_PERFIL_PRO          (Modelo.Rol.ADMIN),
        CREAR_PERFIL_GRATUITO     (Modelo.Rol.GRATUITO),
        VER_ACTIVIDAD_GRATUITOS   (Modelo.Rol.ADMIN),
        CAMBIAR_LIMITE_ROL0       (Modelo.Rol.ADMIN),
        CERRAR_SESION_AJENA       (Modelo.Rol.ADMIN),

        // Acciones del sistema
        ROTAR_CLAVE_MAESTRA       (Modelo.Rol.ADMIN),
        VER_LOG_SEGURIDAD         (Modelo.Rol.ADMIN),
        AUTOBANEO                 (Modelo.Rol.ADMIN);   // ← sí, existe, miralo abajo

        private final Modelo.Rol rolMinimo;

        Accion(Modelo.Rol rolMinimo) {
            this.rolMinimo = rolMinimo;
        }

        public Modelo.Rol rolMinimo() { return rolMinimo; }
    }

    private Roles() {} // no instanciable

    // ============================================================
    // Validación básica
    // ============================================================
    /**
     * ¿Esta sesión puede hacer esta acción, en general?
     * No mira objetivos todavía, solo el rol.
     */
    public static boolean puede(Modelo.Sesion sesion, Accion accion) {
        if (sesion == null || accion == null) return false;
        if (!sesion.activa()) return false;
        if (!sesion.estaVigente()) return false;

        Modelo.Rol rol = sesion.rol();
        if (rol == null) return false;

        // Admin puede todo
        if (rol == Modelo.Rol.ADMIN) return true;

        // Jerarquía estándar: un rol puede lo que puede su nivel o menos
        return rol.nivel() >= accion.rolMinimo().nivel();
    }
    
    
    

    /**
     * Igual que puede(), pero loguea el intento si falla.
     */
    public static boolean puedeOloguea(Modelo.Sesion sesion, Accion accion) {
        if (puede(sesion, accion)) return true;
        loguearIntentoDenegado(sesion, accion, null);
        return false;
    }

    // ============================================================
    // Validación con objetivo
    // ============================================================
    /**
     * ¿Esta sesión puede hacer esta acción SOBRE este perfil?
     * Tiene en cuenta jerarquía y reglas específicas.
     */
    public static boolean puedeSobre(Modelo.Sesion sesion,
                                     Accion accion,
                                     Modelo.Perfil objetivo) {
        if (!puede(sesion, accion)) {
            loguearIntentoDenegado(sesion, accion, objetivo != null ? objetivo.nombre() : null);
            return false;
        }
        if (objetivo == null) return true;

        Modelo.Rol rolActor   = sesion.rol();
        Modelo.Rol rolObjetivo = objetivo.rol();

        // Reglas por acción
        switch (accion) {
            case VER_SU_PROPIO_PERFIL:
                return sesion.perfilId().equals(objetivo.id());

            case EDITAR_SU_PROPIO_PERFIL:
                return sesion.perfilId().equals(objetivo.id());

            case EDITAR_PERFIL_AJENO:
                // Admin puede siempre. Otros, no.
                return rolActor == Modelo.Rol.ADMIN;

            case CAMBIAR_ROL:
            case BANEAR:
            case ELIMINAR:
            case CERRAR_SESION_AJENA:
                // Solo admin, y no puede operar sobre otro admin
                // (excepto autobaneo, que va por otro método).
                if (rolActor != Modelo.Rol.ADMIN) return false;
                return rolObjetivo != Modelo.Rol.ADMIN
                    || sesion.perfilId().equals(objetivo.id());

            case VER_PERFIL_AJENO:
                // EDITOR+ puede ver a todos. Gratuito y PRO solo a sí mismos.
                if (sesion.perfilId().equals(objetivo.id())) return true;
                return rolActor.puedeVerOtrosPerfiles();

            default:
                return true;
        }
    }

    public static boolean puedeSobreOloguea(Modelo.Sesion sesion,
                                            Accion accion,
                                            Modelo.Perfil objetivo) {
        if (puedeSobre(sesion, accion, objetivo)) return true;
        loguearIntentoDenegado(sesion, accion, objetivo != null ? objetivo.nombre() : null);
        return false;
    }

    // ============================================================
    // Atajos comunes (para no escribir el switch cada vez)
    // ============================================================
    public static boolean puedeVerOtros(Modelo.Sesion s) {
        return puede(s, Accion.VER_LISTA_PERFILES);
    }

    public static boolean puedeVerLista(Modelo.Sesion s) {
        return puede(s, Accion.VER_LISTA_PERFILES);
    }

    public static boolean puedeEditarSuPerfil(Modelo.Sesion s) {
        return puede(s, Accion.EDITAR_SU_PROPIO_PERFIL);
    }

    public static boolean puedeAdministrar(Modelo.Sesion s) {
        return s != null && s.rol() == Modelo.Rol.ADMIN;
    }

    public static boolean esAdmin(Modelo.Sesion s) {
        return s != null && s.rol() == Modelo.Rol.ADMIN;
    }

    // ============================================================
    // ============================================================
    // ============  ZONA PELIGROSA: AUTOBANEO  ===================
    // ============================================================
    // ============================================================
    //
    // ⚠️  ATENCIÓN ADMIN  ⚠️
    //
    // Este método le permite al admin banearse a sí mismo.
    // Sí, en serio. No es un chiste. Está implementado de verdad.
    //
    // Si lo usás:
    //   - El admin se marca como BANEADO.
    //   - Su IP e ID se agregan a la lista de baneados.
    //   - Todas sus sesiones se cierran.
    //   - No hay recuperación por web.
    //   - Solo se puede recuperar desde el servidor, editando
    //     indice.json y baneados.json a mano.
    //
    // ¿Por qué existe esto? Porque el dueño del sistema pidió
    // que exista, y porque a veces uno quiere probar sus propios
    // mecanismos de seguridad de la forma más divertida posible.
    //
    // Usalo con cuidado. O no. Es tu sistema.
    //
    // ============================================================
    public static boolean autobanearse(Modelo.Sesion sesion,
                                       GestorJSON gestor,
                                       Autenticacion auth,
                                       String motivo) {

        // Verificación básica: tiene que ser admin activo
        if (!puede(sesion, Accion.AUTOBANEO)) {
            loguearIntentoDenegado(sesion, Accion.AUTOBANEO, null);
            return false;
        }

        if (gestor == null) return false;

        // Buscar el perfil del admin
// Buscar el perfil del admin recorriendo el índice
Modelo.Perfil admin = null;
for (Modelo.EntradaIndice e : gestor.listarTodos()) {
    if (e.rol() == Modelo.Rol.ADMIN) {
        admin = gestor.leerPerfil(e.nombre());
        break;
    }
}
if (admin == null) return false;
        // 1. Marcar estado como BANEADO
        admin.setEstado(Modelo.Estado.BANEADO);
        try {
            gestor.actualizarPerfil(admin);
        } catch (Exception e) {
            System.err.println("[roles] no se pudo marcar admin como baneado: " + e.getMessage());
            return false;
        }

        // 2. Agregar a la lista de baneados (ID + IP)
        Modelo.Baneado b = Modelo.Baneado.nuevo(
            admin.id(),
            admin.ipCreacion(),
            (motivo == null || motivo.isBlank())
                ? "Autobaneo del administrador. Motivo: diversión."
                : motivo
        );
        gestor.agregarBaneado(b);

        // 3. Cerrar todas las sesiones del admin
        if (auth != null) {
            auth.cerrarTodasDe(admin.id());
        }

        // 4. Loguear el evento
        loguearEvento("[AUTOBANEO] admin=" + admin.nombre()
            + " id=" + admin.id()
            + " ip=" + admin.ipCreacion()
            + " motivo=" + b.motivo());

        System.out.println("════════════════════════════════════════════════");
        System.out.println("  ADMIN AUTOBANEADO: " + admin.nombre());
        System.out.println("  El sistema sigue funcionando, pero sin admin.");
        System.out.println("  Recuperación: editar indice.json y baneados.json");
        System.out.println("  a mano desde el servidor.");
        System.out.println("════════════════════════════════════════════════");

        return true;
    }
    // ============================================================
    // ============  FIN ZONA PELIGROSA  ==========================
    // ============================================================

    // ============================================================
    // Log de seguridad
    // ============================================================
    private static void loguearIntentoDenegado(Modelo.Sesion sesion,
                                               Accion accion,
                                               String objetivoNombre) {
        String actor = (sesion == null) ? "(sin sesión)"
                     : (sesion.perfilId() + " rol=" + sesion.rol());
        String obj = (objetivoNombre == null) ? "-" : objetivoNombre;
        loguearEvento("[DENEGADO] actor=" + actor
            + " accion=" + accion
            + " objetivo=" + obj);
    }

    private static void loguearEvento(String mensaje) {
        try {
            Files.createDirectories(LOG_SEGURIDAD.getParent());
            String linea = LocalDateTime.now().format(FMT) + " " + mensaje + "\n";
            Files.write(
                LOG_SEGURIDAD,
                linea.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println("[roles] no se pudo escribir en el log: " + e.getMessage());
        }
    }

    /**
     * Lee el log de seguridad. Solo para el admin.
     */
    public static String leerLogSeguridad(Modelo.Sesion sesion) {
        if (!puede(sesion, Accion.VER_LOG_SEGURIDAD)) {
            loguearIntentoDenegado(sesion, Accion.VER_LOG_SEGURIDAD, null);
            return "";
        }
        try {
            if (!Files.exists(LOG_SEGURIDAD)) return "(log vacío)";
            return new String(Files.readAllBytes(LOG_SEGURIDAD), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "(error leyendo log: " + e.getMessage() + ")";
        }
    }
}