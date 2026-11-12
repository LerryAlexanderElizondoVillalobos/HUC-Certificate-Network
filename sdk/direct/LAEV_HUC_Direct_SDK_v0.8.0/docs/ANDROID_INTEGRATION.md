# Integración Android — HUC Direct SDK 0.8

## Añadir la biblioteca

Desde `android/`, incluir `:huc-direct` en Gradle. El módulo utiliza:

- Android Keystore para generar y custodiar claves RSA del titular;
- Bouncy Castle para Ed25519 y generación de CSR PKCS#10;
- OkHttp para consumir la API opcional;
- `CertificateFactory` y `Signature` para validar X.509 y la prueba de posesión.

Min SDK declarado: 26. Compilar con JDK 17 y Android Gradle Plugin configurado en el proyecto.

## Ciclo de vida del titular

```kotlin
val holderKey = HucDirectClient.createHolderKey("university-diploma-2026")
val csrPem = HucDirectClient.createCsr("Student Full Name", holderKey.alias)
```

La clave privada es no exportable desde Android Keystore. El CSR se envía al backend de matrícula/registro académico; el backend reenvía el CSR al servicio emisor. No incorporar `X-HUC-Admin-Token` dentro de la app.

Cuando se recibe la credencial:

```kotlin
val bundle = android.util.Base64.decode(bundleB64, android.util.Base64.DEFAULT)
val result = HucDirectClient.verifyBundle(bundle, issuerTrustPin)
require(result.result == "VALID")
```

El pin se configura por MDM, app config firmada, QR institucional autenticado o instalación administrada. No usar el pin que viene dentro del paquete como única raíz de confianza.

## Presentación directa

La aplicación verificadora crea un `challenge` con la huella y audiencia. El titular firma con su alias de Android Keystore:

```kotlin
// Before signing, display the challenge's audience to the holder and request consent.
val response = HucDirectClient.respondToChallenge(
    challenge = challengeJson,
    credentialBundle = bundle,
    keystoreAlias = holderKey.alias
)
```

Después, el verificador envía challenge y response a su backend mediante `HucDirectApiClient.verifyDirect(...)`.

## Integración de red

`HucDirectApiClient` usa llamadas OkHttp síncronas. Ejecutarlas en `Dispatchers.IO`, un `Executor` o WorkManager, nunca en el hilo principal. Usar HTTPS para producción. Las excepciones de API deben convertirse en estados de UI seguros; no exponer mensajes internos ni tokens en logs.

## Consideraciones Android

- Hacer backup de la credencial pública, no de la clave privada de Keystore.
- Reinstalar la app o cambiar de dispositivo puede hacer que la clave privada anterior no esté disponible; la institución deberá emitir una nueva credencial ligada a una nueva clave.
- Android Keystore puede tener capacidades distintas por fabricante y nivel de seguridad; probar el algoritmo RSA y las operaciones de firma en los dispositivos soportados.
- La app debe mostrar el campo `audience` y pedir consentimiento antes de firmar un challenge. Para operaciones de alto riesgo, activar autenticación del usuario/biometría en la política de clave Android Keystore.
- El módulo Kotlin se entrega como fuente Gradle de referencia. Antes de publicar, ejecutar build/test en Android Studio y pruebas instrumentadas en API 26, API 28, API 33 y API 35, tanto en emulador como en dispositivos físicos.
