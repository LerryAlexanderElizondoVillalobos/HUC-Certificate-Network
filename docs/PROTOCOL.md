# LAEV HUC 0.8 — Especificación protocolaria de referencia

**Identificador:** `LAEV-HUC-BFT-0.8`  
**Estado:** borrador experimental implementado en el prototipo.  
**Transporte:** HUC Peer TCP/TLS con firma Ed25519 de aplicación.  
**Estado:** UTXO lógico replicado; no blockchain.

## 1. Parámetros de red

Para `n` validadores y tolerancia `f`:

- `n = 3f + 1`
- `quorum = 2f + 1`
- cuatro validadores: `f=1`, quorum `3`.

Los validadores se identifican por `validator_id`; sus claves públicas Ed25519 forman parte del manifiesto fijado por hash externo. La lista ordenada de IDs determina el primario de cada vista:

`primary(view) = sorted(validator_ids)[view mod n]`.

## 2. Mensajes y firmas

Los mensajes de cada fase incluyen el identificador de red, epoch, vista, secuencia, request hash y validador emisor. Las firmas usan Ed25519 con separación de dominio (`domain separation`) por tipo de mensaje. El identificador de PRE-PREPARE, PrepareCertificate, PreparedCertificate, CommitCertificate y NewView se calcula sobre JSON canónico del objeto correspondiente.

El prototipo usa la serialización canónica implementada por `huc.canonical_json` (claves ordenadas, separadores compactos, UTF-8). Esta convención es interna al paquete; una especificación interoperable multi-lenguaje debe fijar y probar formalmente la canonicalización, por ejemplo adoptando un perfil compatible con RFC 8785.

## 3. PRE-PREPARE

El primary actual crea una propuesta que incluye:

- `network_id`, `epoch`, `view`, `sequence`;
- `primary_id`;
- `parent_state_hash`;
- `proposal_id`, `request_hash` y propuesta UTXO;
- timestamp de creación.

El primary firma el payload. Cada validador comprueba que el firmante es el primary esperado, la vista y secuencia sean actuales, el parent hash coincida, la propuesta no haya expirado y la transición UTXO sea admisible. Si la red exige PKI, se verifica también X.509 y HUC-CC.

## 4. PREPARE y PrepareCertificate

Cada validador puede firmar como máximo una solicitud para cada `view:sequence`. La firma PREPARE referencia el ID del PRE-PREPARE y su request hash. El voto se persiste antes de responder.

Un `PrepareCertificate` requiere `quorum` votos de validadores distintos, todos vinculados al mismo PRE-PREPARE, red, epoch, vista, secuencia y request hash.

## 5. Prepared lock ACK y PreparedCertificate

Después de validar el PrepareCertificate, cada validador verifica que haya firmado PREPARE por esa misma solicitud. Antes de emitir su `Prepared lock ACK`, persiste un lock por secuencia y request hash. No firma un lock conflictivo para esa secuencia.

Un `PreparedCertificate` incluye el PrepareCertificate y `quorum` lock ACKs firmados por validadores diferentes. La evidencia completa debe persistir y puede incluirse en un VIEW_CHANGE.

Este ACK es una extensión de HUC para que el estado preparado sea explícito. No es una fase idéntica del PBFT original.

## 6. COMMIT y CommitCertificate

Un validador firma COMMIT únicamente después de verificar el PreparedCertificate. El voto se vincula a red, epoch, vista, secuencia, request hash y PreparedCertificate ID, y se persiste para impedir equivocar la misma secuencia.

Un `CommitCertificate` requiere quorum de votos COMMIT distintos y contiene el PreparedCertificate. Una réplica verifica:

1. firma y estructura del CommitCertificate;
2. quórum COMMIT y ausencia de firmantes duplicados;
3. PrepareCertificate y PreparedCertificate;
4. continuidad de epoch, secuencia y parent-state hash;
5. transición UTXO e integridad X.509/HUC-CC cuando aplique.

Solo después aplica el commit.

## 7. View Change

Cada validador produce `VIEW_CHANGE` para exactamente `current_view + 1`. El mensaje firma:

- `network_id`, epoch, `from_view`, `target_view`;
- `validator_id`;
- `last_committed_sequence`, `last_committed_hash`;
- PreparedCertificate o evidencia local de preparación, si existe;
- motivo y timestamp.

Los mensajes del quorum deben referirse al mismo checkpoint comprometido. Un NEW_VIEW requiere quorum de VIEW_CHANGE distintos. Su primary es el que corresponde a la vista objetivo según el orden determinista de validadores.

## 8. Selección y recuperación

NEW_VIEW verifica todos los VIEW_CHANGE y selecciona el PreparedCertificate de mayor vista que aparezca en el quorum. Si aparecen certificados de request hash incompatibles en la misma vista máxima, el nodo entra en safety halt. Si un validador conserva localmente un PreparedCertificate completo que NEW_VIEW omite o contradice, rechaza instalar esa vista.

Si NEW_VIEW selecciona una operación preparada, el nuevo primary debe reproponer la misma solicitud vinculándola al ID del PreparedCertificate seleccionado. La propuesta recuperada ejecuta PRE-PREPARE, PREPARE, prepared-lock, COMMIT y APPLY en la nueva vista. Si no existe operación preparada que recuperar, el nuevo primary puede proponer una operación nueva.

Un validador no libera un lock completo por expiración de propuesta. Los locks tentativos solo pueden resolverse mediante una NEW_VIEW válida que demuestre el estado del quorum. Ante conflicto no resuelto, HUC se detiene.

## 9. Estado y sincronización

Un paquete de estado BFT contiene los commits firmados, certificados de vista y datos públicos necesarios. No contiene claves privadas. El receptor reconstruye el estado desde genesis y verifica cada transición. También verifica continuidad de la secuencia de vistas, checkpoints y locks locales.

Se rechazan rollback, fork, hashes incorrectos, firmas inválidas y divergencias contra estado local ya comprometido.

## 10. Supuestos y límites

La meta de seguridad para el perfil de cuatro validadores presupone como máximo un validador Byzantine (`f=1`), claves honestas no comprometidas, locks persistidos de forma durable, mismo manifiesto de red, misma génesis y validación correcta de mensajes. La liveness requiere una red suficientemente síncrona tras el periodo de retraso y al menos quorum alcanzable.

El prototipo no ha sido formalmente verificado ni auditado. No afirma equivalencia exacta con PBFT. La prueba TLS con cuatro procesos se ejecuta en loopback; no acredita operación en cuatro dispositivos físicos ni WAN. Ver `PHYSICAL_DEVICE_TEST.md`.
