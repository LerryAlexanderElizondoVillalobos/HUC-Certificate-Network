# LAEV HUC 0.8 — Arquitectura de consenso y recuperación

## 1. Objetivo

HUC 0.8 añade una máquina de consenso BFT-inspired al estado replicado HUC. El objetivo es que instituciones independientes mantengan réplicas del mismo estado de certificación, validen X.509/HUC-CC y puedan recuperar operaciones preparadas cuando el primario falla, sin blockchain, moneda, minería ni coordinador permanente.

## 2. Capas

```text
┌──────────────────────────────────────────────────────┐
│ X.509                                                │
│ Identidad/clave pública/emisor/vigencia/firma CA     │
└──────────────────────────┬───────────────────────────┘
                           │ certificate hash
┌──────────────────────────▼───────────────────────────┐
│ HUC-CC                                               │
│ Política de autoridad, permisos y aprobaciones       │
└──────────────────────────┬───────────────────────────┘
                           │ consensus certificate hash
┌──────────────────────────▼───────────────────────────┐
│ HUC BFT STATE MACHINE                                │
│ PRE-PREPARE → PREPARE → PREPARED → COMMIT            │
│ ViewChange / NewView / PreparedCertificate recovery  │
└──────────────────────────┬───────────────────────────┘
                           │ committed transition
┌──────────────────────────▼───────────────────────────┐
│ HUC UTXO STATE                                       │
│ ISSUE / RENEW / REVOKE / sequence / head hash        │
└──────────────────────────┬───────────────────────────┘
                           │ signed peer messages
┌──────────────────────────▼───────────────────────────┐
│ HUC PEER TRANSPORT                                   │
│ TCP + TLS transport + Ed25519 application signatures│
└──────────────────────────────────────────────────────┘
```

## 3. Identidad y topología

Cada validador conserva su propia clave Ed25519 en su directorio local. El manifiesto de red solo contiene descriptores y claves públicas. Los mensajes HUC están firmados con domain separation y vinculan la red, vista, secuencia, operación y remitente.

El transporte peer usa conexiones TCP directas. Para hosts fuera de loopback, el servicio exige TLS salvo override de laboratorio/VPN. El cliente valida el certificado de servidor mediante CA y hostname/IP. La identidad HUC del remitente se verifica por la firma Ed25519 incluida en el sobre de aplicación. El servidor no exige certificado de cliente mTLS en esta versión.

## 4. Perfil de quórum

El perfil admite `n=3f+1`, con `q=2f+1`. Para cuatro nodos:

- `n=4`
- `f=1`
- `q=3`

El protocolo puede progresar con un nodo no disponible. Con solo dos votos válidos no compromete una operación. El supuesto de seguridad es como máximo `f` validadores Byzantine, claves no comprometidas, almacenamiento de locks durable y estado/genesis/manifiesto comunes.

## 5. Ciclo de transacción

1. **PRE-PREPARE:** el primario determinista de la vista firma una propuesta vinculada al `parent_state_hash`, `sequence`, `view`, `epoch` y `request_hash`.
2. **PREPARE:** cada nodo valida el PRE-PREPARE, el estado UTXO y, cuando la red está configurada con PKI, el certificado X.509 y HUC-CC. Luego persiste su voto por vista/secuencia antes de responder.
3. **PrepareCertificate:** reúne `q` votos PREPARE distintos que coinciden en la misma propuesta.
4. **Prepared lock ACK:** cada validador que ha preparado la propuesta persiste el lock y firma un acknowledgement.
5. **PreparedCertificate:** agrupa el PrepareCertificate y `q` lock ACKs firmados. Esto crea evidencia explícita del estado preparado para la recuperación.
6. **COMMIT:** cada validador verifica el PreparedCertificate, persiste su voto COMMIT y firma la confirmación.
7. **CommitCertificate:** agrupa `q` votos COMMIT distintos.
8. **Apply:** cada réplica vuelve a verificar el certificado de compromiso, continuidad del estado y reglas UTXO antes de aplicar la transición.

La etapa `PREPARED lock ACK` es una extensión específica de HUC para hacer explícitos y transportables los locks. No debe confundirse con una equivalencia literal de cada fase a la especificación original de PBFT.

## 6. Bloqueos y anti-equivocación

Los nodos persisten votos PREPARE por `view:sequence`, prepared locks por secuencia, votos COMMIT por secuencia y mensajes VIEW_CHANGE por vista destino. Una segunda firma conflictiva para el mismo slot se rechaza. Los locks no se liberan por simple expiración de una propuesta.

Los archivos locales protegidos y `FileLock` son controles de laboratorio. Producción requiere almacenamiento transaccional durable, protección contra rollback y procedimientos probados de restauración.

## 7. View Change y recuperación

Cuando el primario deja de progresar, los validadores crean mensajes `VIEW_CHANGE` firmados que incluyen:

- red y epoch;
- vista anterior y vista objetivo;
- última secuencia y `head_hash` comprometidos;
- evidencia de prepared state, si existe;
- identificador del validador y firma.

El nuevo primary se determina de forma reproducible sobre la lista ordenada de validadores. Un NEW_VIEW requiere quorum `q` de mensajes VIEW_CHANGE sobre el mismo checkpoint. El NEW_VIEW identifica y selecciona el PreparedCertificate de mayor vista comunicado por el quorum.

Cada nodo verifica el NEW_VIEW y comprueba que no omita ni contradiga un PreparedCertificate completo que ya tenga persistido. Si hay locks o certificados incompatibles, el resultado es un safety halt y no un commit arbitrario. Si hay una operación preparada seleccionada, el nuevo primary la vuelve a proponer en la nueva vista y ejecuta el ciclo completo.

El cambio de vista no puede avanzar con réplicas que no compartan el mismo checkpoint comprometido; primero deben sincronizar y verificar el historial.

## 8. Estado replicado y sincronización

El estado HUC conserva un ledger append-only de CommitCertificates, una cabeza hash, secuencia, estado de certificados y control de vistas. Un peer puede exportar un paquete público, sin claves privadas. El receptor reconstruye el estado reproduciendo y verificando cada commit, controles de vista y continuidad del checkpoint.

La sincronización rechaza:

- secuencia o cabeza anteriores a la réplica local (rollback);
- historia que diverge en una posición ya comprometida (fork);
- CommitCertificates, firmas o hashes alterados;
- certificados de vista que no continúan la vista/checkpoint;
- discrepancias con locks locales persistidos.

El snapshot es una ayuda de transporte; la fuente verificable es la secuencia de commits firmados y los certificados de vista.

## 9. Integración X.509 + HUC-CC

Cuando el manifiesto de red contiene el perfil PKI, cada propuesta incluye los bytes públicos del X.509 y el HUC-CC. Cada validador valida localmente:

- cadena y firma X.509 bajo la CA configurada;
- período de validez de CA y certificado;
- SHA-256 DER del X.509;
- hash canónico y firmas del HUC-CC;
- vinculación HUC-CC/X.509 y política;
- operación permitida y campos requeridos.

El estado UTXO replicado por BFT registra el ciclo de vida compartido. La evidencia HUC-CC acredita la autorización emitida bajo la política de certificación; el estado BFT es la referencia replicada para el ciclo de vida de la red.

## 10. Lo que no es

- No es una blockchain ni un sistema de tokens.
- No es minería ni Proof of Work.
- No es una implementación PBFT formalmente verificada.
- No es una prueba de conectividad física entre instituciones.
- No es una PKI pública ni reemplaza OCSP/CRL para clientes X.509 tradicionales.

## 11. Referencia y límite académico

El protocolo toma como referencia las ideas de PRE-PREPARE, PREPARE, COMMIT, quórum `3f+1` y view change descritas en PBFT. HUC añade una fase de prepared-lock ACK y una estructura HUC específica de evidencias. Se requiere revisión formal independiente antes de afirmar equivalencia o seguridad probada.
