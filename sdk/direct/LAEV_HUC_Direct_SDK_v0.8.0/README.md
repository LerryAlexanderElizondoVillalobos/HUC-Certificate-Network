# LAEV HUC Direct SDK 0.8.0

**Emitir, presentar y verificar certificados dentro de aplicaciones, sin exigir nodos, blockchain ni criptomonedas.**

HUC Direct SDK convierte la arquitectura Standalone en una biblioteca integrable:

- **Python SDK:** emisión local, CSR, renovación, revocación, paquete de credencial, verificación offline y challenge-response.
- **Android SDK (Kotlin):** generación de clave/CSR con Android Keystore, verificación local del paquete y firma de desafíos sin exportar la clave privada.
- **REST API opcional:** interfaz para integrar emisores y verificadores con HR/ERP, universidades, plataformas de capacitación y portales de certificación.
- **TypeScript client:** funciones de consumo de la API empresarial.

La comunicación directa es opcional. La verificación básica utiliza el paquete firmado y una huella de confianza distribuida por un canal independiente.

## 1. Arquitectura

```text
TITULAR / ANDROID APP
  Android Keystore: clave privada no exportable
  genera CSR -> recibe credencial -> presenta credencial
                 |
                 | CSR / paquete HUC
                 v
EMISOR INSTITUCIONAL (Python SDK / API protegida)
  CA X.509 + clave HUC-CC + ledger UTXO local
  emisión / renovación / revocación / atestación firmada
                 |
                 v
PAQUETE AUTÓNOMO HUC
  X.509 + HUC-CC + UTXO State Attestation + Trust Anchor
                 |
                 v
APLICACIÓN VERIFICADORA
  Android / Python / API empresarial / educación
  valida firmas, vínculo, vigencia y estado
                 |
       +---------+----------+
       |                    |
   OFFLINE              HUC DIRECT
   paquete local        challenge-response opcional
                        titular <-> aplicación
```

**No hay red de validadores, servidor de consenso, líder, blockchain, minería ni pago por transacción.** El servicio API es opcional: se utiliza para centralizar la operación administrativa del emisor, no para verificar una credencial que ya se tiene localmente.

## 2. Componentes

| Componente | Responsabilidad |
|---|---|
| X.509 | Identidad, clave pública, emisor, vigencia y firma CA |
| HUC-CC | Evidencia complementaria firmada que vincula X.509, política y outpoint de emisión |
| HUC-UTXO | Estado local `ACTIVE`, `SUPERSEDED` o `REVOKED`; renovación consume y crea una salida |
| State Attestation | Evidencia de estado firmada por el emisor, con secuencia, cabeza del ledger y TTL |
| HUC Direct | Desafío único, prueba de posesión de clave y protección local contra replay |

**Precisión importante:** en la versión 0.8 HUC-CC es una atestación protocolaria firmada por el emisor (una autoridad), no un consenso BFT ni una votación entre instituciones. Esta elección elimina por completo la infraestructura de nodos. El emisor sigue siendo autoridad de estado.

## 3. Python SDK

Instalar:

```bash
cd python
python -m pip install .
# API empresarial opcional:
python -m pip install '.[api]'
```

Ejemplo mínimo:

```python
from huc_direct import HucIssuer, HucVerifier, HucPresenter, generate_csr

issuer, trust_pin = HucIssuer.initialize(
    "./issuer-workspace", issuer_id="ACME-CREDENTIALS")

# En el equipo del titular: clave privada local + CSR.
csr_path, holder_private_key = generate_csr("Alex Example", "./holder")

# El emisor recibe el CSR público. La clave privada no se transmite.
credential = issuer.issue(csr_path.read_bytes(), days=365)

# El verificador comprueba el ZIP sin consultar una red.
verifier = HucVerifier(trust_pin, max_state_age_seconds=300)
result = verifier.verify_bundle(credential.bundle)
assert result["result"] == "VALID"

# Presentación directa opcional: nonce + audiencia + prueba de posesión.
challenge = verifier.create_challenge(
    credential.certificate_sha256, "hr.acme.example")
response = HucPresenter.create_response(
    challenge, credential.bundle, holder_private_key)
proof = verifier.verify_response(
    response, challenge, "hr.acme.example", "./replay-store.json")
assert proof["holder_proof_of_possession"]
```

El contenido completo de la API Python está en `python/huc_direct/`.

## 4. Android SDK

Proyecto Gradle en `android/`:

- `:huc-direct`: biblioteca Kotlin.
- `:sample`: aplicación de ejemplo.

El SDK utiliza Android Keystore para crear una clave RSA del titular no exportable, crea una CSR y firma desafíos con esa clave. También verifica el paquete HUC offline. Bouncy Castle se utiliza para parseo/validación Ed25519 y para la CSR; OkHttp está incluido para llamadas REST en segundo plano.

Ejemplo:

```kotlin
val holderKey = HucDirectClient.createHolderKey("huc-student-2026")
val csrPem = HucDirectClient.createCsr("Student Example", holderKey.alias)

// Enviar csrPem al backend institucional; el token de administración no va en la app.
// La respuesta incluye credential_bundle_b64 y trust_anchor_sha256.

val verification = HucDirectClient.verifyBundle(
    bundleBytes,
    trustedIssuerPin,
    maxStateAgeSeconds = 300
)
check(verification.result == "VALID")

val challenge = HucDirectClient.createChallenge(
    verification.certificateSha256,
    "student-portal.university.example"
)
val response = HucDirectClient.respondToChallenge(
    context, challenge, bundleBytes, holderKey.alias
)
// El verificador envía challenge + response a su backend por HTTPS.
```

El pin debe venir de una fuente confiable configurada en la aplicación, no del propio ZIP que se está comprobando. Las solicitudes de red deben ejecutarse fuera del hilo UI.

**Estado de compilación:** el código Kotlin y el proyecto Gradle están incluidos, pero no pude ejecutar una compilación Android ni pruebas en dispositivos físicos porque este entorno no tiene Android SDK ni Gradle. Antes de publicación hay que compilar con Android Studio/Gradle y validar Android Keystore/Ed25519 en las versiones objetivo. Consulta `android/README.md`.

## 5. REST API empresarial

El adaptador opcional FastAPI expone:

| Método | Endpoint | Uso |
|---|---|---|
| GET | `/healthz` | Estado del servicio |
| GET | `/v1/trust` | Pin y política pública del emisor |
| POST | `/v1/credentials/issue` | Emitir con CSR (protegido por token admin) |
| POST | `/v1/credentials/renew` | Renovar (protegido por token admin) |
| POST | `/v1/credentials/revoke` | Revocar (protegido por token admin) |
| POST | `/v1/credentials/refresh` | Obtener una nueva atestación de estado (protegido por token admin) |
| POST | `/v1/credentials/verify` | Verificar ZIP público |
| POST | `/v1/direct/challenges` | Crear desafío |
| POST | `/v1/direct/verify` | Verificar respuesta y consumir nonce |

Ejecutar servidor de desarrollo:

```bash
cd python
python -m pip install '.[api]'
python - <<'PY'
from huc_direct import HucIssuer
HucIssuer.initialize("./issuer-workspace", "ACME-ISSUER")
PY
export HUC_ISSUER_WORKSPACE=./issuer-workspace
export HUC_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python run_api.py
```

El servicio escucha por defecto en `127.0.0.1:8088`. Para despliegue debe ir detrás de HTTPS/mTLS, proxy inverso, firewall, rate limiting, logs con redacción de datos y gestor de secretos. El token administrativo solo se utiliza desde un backend de confianza; nunca se incrusta en una app Android o frontend público.

## 6. Casos empresariales y educativos

- **RR. HH.:** formación obligatoria, habilitaciones internas, constancias y acreditaciones.
- **Universidades:** diplomas, certificados de cursos, microcredenciales y constancias académicas.
- **Capacitación profesional:** credenciales con vigencia, renovación y revocación.
- **Software de certificación:** emitir y validar mediante SDK o REST, integrando el resultado al expediente existente.

Los ejemplos en `examples/enterprise/` y `examples/education/` muestran cómo enlazar el resultado verificado a un registro de negocio. La verificación criptográfica no reemplaza el proceso de identificación de la persona ni la regla de autorización de la organización.

## 7. Pruebas

```bash
python -m pip install -e 'python[api,test]'
PYTHONPATH=python python -m unittest discover -s tests -v
```

Las pruebas cubren emisión, X.509, HUC-CC, estado UTXO, renovación, revocación, integridad, desafío directo, prueba de posesión, audiencia, replay store, API protegida y concurrencia de revocación.

## 8. Límites de seguridad

- El emisor es autoridad sobre el estado UTXO; no hay consenso multiinstitucional en 0.8.
- Una atestación `ACTIVE` desconectada no conoce revocaciones posteriores; su TTL limita esa ventana. Evidencia caducada da `INDETERMINATE`.
- El challenge demuestra control de la clave privada, no identidad civil ni derecho a ejecutar una acción.
- El almacenamiento de claves del prototipo Python es PEM sin cifrar. Para producción se requiere HSM/KMS o almacén protegido.
- Los consumidores X.509 tradicionales no consultan automáticamente el UTXO HUC; no hay OCSP/CRL bridge.
- El transporte QR/NFC/Bluetooth no cifra por sí mismo. Las aplicaciones deben proteger el canal.
- La canonicalización JSON es el perfil HUC restringido; la interoperabilidad de producción requiere RFC 8785/JCS completo y vectores cruzados.
- No es una CA pública ni está preparado para TLS público, identidad legal, licencias oficiales o acceso crítico sin revisión independiente.

Consulta `docs/SECURITY.md`, `docs/API_INTEGRATION.md` y `docs/ANDROID_INTEGRATION.md` antes de una integración real.
