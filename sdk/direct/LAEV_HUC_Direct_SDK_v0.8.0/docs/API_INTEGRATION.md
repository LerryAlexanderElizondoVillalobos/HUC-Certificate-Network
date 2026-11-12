# Integración REST empresarial — HUC Direct 0.8

## Topología recomendada

```text
HR / LMS / SIS / ERP / Portal
          |
          | HTTPS + identidad de servicio
          v
API Gateway / Backend institucional
          |
          +---- HUC verifier (local SDK o REST)
          |
          +---- HUC issuer service (red interna, admin token)
                         |
                  CA + clave HUC
                  ledger UTXO local
```

La clave de CA y la clave del emisor deben permanecer en el servicio de emisión, idealmente en HSM/KMS. El verificador no necesita acceso a ninguna clave privada. El pin SHA-256 de confianza se entrega mediante configuración institucional, MDM, paquete firmado o canal autenticado independiente.

## Emisión desde un backend

El titular genera una clave y un CSR localmente (Python `generate_csr` o Android Keystore `createCsr`). El backend recibe el CSR y llama al endpoint de emisión desde su red privada:

```http
POST /v1/credentials/issue
X-HUC-Admin-Token: <secret held only by backend>
Content-Type: application/json
```

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "days": 365
}
```

La respuesta contiene `certificate_pem`, `consensus_certificate`, `state_attestation`, `credential_bundle_b64` y `trust_anchor_sha256`. El backend entrega el ZIP público al titular por el canal de la aplicación. Nunca solicita ni recibe la clave privada del titular.

## Verificación de un paquete

```http
POST /v1/credentials/verify
Content-Type: application/json
```

```json
{ "bundle_b64": "UEsDB..." }
```

La respuesta es `VALID`, `INVALID` o `INDETERMINATE`. Para políticas estrictas, aceptar solo `VALID` y asociar el hash verificado con el expediente de negocio.

## Challenge-response

1. La aplicación verificadora solicita `/v1/direct/challenges` con el hash del certificado y una audiencia exacta.
2. Envía el JSON del desafío al titular (QR, NFC, Bluetooth o HTTPS).
3. El titular firma con su clave privada y devuelve la respuesta con el paquete HUC.
4. La aplicación entrega `challenge`, `response` y `audience` a `/v1/direct/verify`.
5. El servidor verifica HUC, la firma de posesión, la audiencia, el vencimiento y consume el nonce.

El `replay_store` debe ser persistente y compartido por todas las instancias que atienden el mismo dominio de audiencia. Si hay varias réplicas web, no usar archivos locales independientes: utilizar una base transaccional (por ejemplo, PostgreSQL con restricción única sobre nonce) o afinidad estricta de instancia.

Cuando una credencial antigua devuelve `INDETERMINATE`, el backend autorizado puede llamar a `/v1/credentials/refresh` con el X.509 para obtener una nueva atestación y paquete. La respuesta será `ACTIVE`, `SUPERSEDED` o `REVOKED` según el ledger actual del emisor.

## Seguridad de la API

- TLS 1.2+ obligatorio en producción; preferir mTLS para integraciones de sistemas.
- `X-HUC-Admin-Token` solo entre backend institucional y emisor, guardado en secret manager.
- Nunca poner el token administrativo en Android, JavaScript de navegador o apps de terceros.
- Limitar tasa y tamaño, autenticar al cliente, autorizar por issuer/tenant y auditar emisiones/revocaciones.
- No registrar CSR completos, paquetes o claves; redactar datos personales y firmas si no son necesarias.
- Proteger el workspace del emisor y separar privilegios operativos.
- Hacer backup y plan de rotación/revocación de claves CA/issuer.
- No publicar el servidor de desarrollo Uvicorn directamente a internet.

## Multi-tenant

El ejemplo actual representa un emisor y una política por workspace. Un servicio multi-tenant debe aislar un workspace/pin por entidad emisora, validar que la credencial solicitada pertenece al tenant autenticado y no permitir que parámetros del cliente elijan arbitrariamente otro trust anchor.
