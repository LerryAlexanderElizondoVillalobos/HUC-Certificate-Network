# Seguridad y modelo de amenazas — LAEV HUC 0.8.0

## Clasificación

Prototipo experimental de consenso BFT-inspired. No es un sistema auditado ni formalmente verificado, y no debe usarse para identidad legal, TLS público, control de acceso crítico ni producción.

## Activos

- Claves privadas Ed25519 de validadores y autoridades HUC-CC.
- Clave privada de la CA X.509 y claves privadas de titulares.
- Network manifest, trust pins, peer map y TLS CA/certificados.
- Prepare votes, prepared locks, CommitCertificates, ViewChange/NewView certificates y ledgers.
- Estado UTXO y checkpoints de las réplicas.

## Controles implementados en el prototipo

- Firmas Ed25519 de nodos y autoridades, con separación por dominio.
- PRE-PREPARE firmado por el primary esperado para la vista.
- PREPARE vinculado al ID del PRE-PREPARE, red, epoch, view, sequence y request hash.
- Quórum de votos PREPARE y rechazo de duplicados.
- Persistencia de prepared lock antes de emitir su ACK firmado.
- PreparedCertificate con evidencia de preparación y lock quorum.
- COMMIT vinculado al PreparedCertificate y quórum de confirmación.
- Verificación independiente del CommitCertificate antes de aplicar el cambio de estado.
- Anti-equivocación durable para PREPARE, prepared locks y COMMIT.
- Bloqueo persistente compartido para serializar lectura, validación, firma y escritura de PREPARE, prepared-lock ACK, PreparedCertificate, COMMIT, VIEW_CHANGE y NEW_VIEW.
- Prueba concurrente que entrega dos PRE-PREPARE conflictivos a una réplica al mismo tiempo y verifica que solo una propuesta puede obtener la firma.
- ViewChange firmado, checkpoint comprometido, selección del prepared certificate de mayor vista y safety halt ante conflictos.
- NewView firmado por el primary de destino y verificado por cada réplica.
- Estado exportado sin claves privadas y sincronización que verifica commits y certificados de vista, y rechaza rollback/fork.
- Mensajes P2P firmados, request IDs, caché anti-replay y límites de tamaño/timeout.
- TLS para servicios fuera de loopback, con validación de CA y hostname/IP en clientes.
- Cada validador puede validar X.509 y HUC-CC antes de votar.

## Modelo y supuestos

Para `n=3f+1`, el quorum es `2f+1`. En el perfil de cuatro nodos, `f=1` y el quorum es tres. La seguridad presupone que no más de un validador es bizantino, que las claves privadas honestas no están comprometidas, que los locks sobreviven a reinicios/rollback del almacenamiento y que todos los nodos verifican el mismo manifiesto de red y estado anterior.

Un quórum de tres puede tolerar un nodo que no responda en disponibilidad, pero el progreso se detiene cuando quedan menos de tres votos válidos. La seguridad se prioriza sobre la disponibilidad.

## Pruebas adversariales incluidas

- Propuesta/PREPARE/COMMIT con quórum insuficiente.
- PRE-PREPARE emitido por un nodo que no es primary.
- Firmas alteradas y mensajes de fases inválidos.
- Repetición de mensajes P2P.
- Intentos de doble voto y propuestas conflictivas en la misma secuencia.
- Prepared certificates conflictivos y safety halt.
- Cambio de vista sin quorum, con primary incorrecto o con evidencia alterada.
- Recuperación de operación preparada en nueva vista.
- Partición inferior a quorum que no confirma.
- Sincronización de paquete alterado, fork o rollback.
- Cuatro procesos independientes con transporte TLS sobre TCP loopback.

## Límites no resueltos

1. **No es PBFT formalmente verificado.** Es un diseño de laboratorio PBFT-inspired con una etapa extra de prepared-lock ACK. Requiere revisión externa de reglas de seguridad, cambio de vista, recovery, persistencia y casos Byzantine.
2. **Dispositivos físicos no probados.** La prueba de cuatro procesos usa loopback en una sola máquina. No prueba WAN, NAT, firewalls institucionales, pérdida/latencia real ni heterogeneidad de dispositivos.
3. **Sin mTLS obligatorio.** Los peers validan TLS del servidor y autentican mensajes de aplicación por Ed25519; no se exige certificado de cliente TLS. Para despliegue institucional se recomienda mTLS además de firma de aplicación.
4. **Persistencia local.** Los file locks y archivos locales no sustituyen almacenamiento durable resistente a rollback, HSM/KMS, backups auditados ni replicación segura de discos.
5. **Relojes.** Hay controles de ventana temporal en mensajes; la sincronización de hora y manejo de skew deben probarse en entornos reales.
6. **NAT/descubrimiento.** No hay NAT traversal, relay ni descubrimiento automático. Se requiere direccionamiento IP alcanzable o VPN administrada.
7. **Identidad civil.** Las firmas demuestran control de claves, no identidad civil, licencia profesional o autoridad legal de la institución.
8. **Privacidad.** No incluir datos personales en metadatos públicos. Evaluar minimización, retención, acceso y exposición del X.509.
9. **Offline.** No se puede detectar una revocación posterior al último checkpoint que recibió un verificador desconectado.

## Requisitos antes de producción

- Revisión formal del protocolo y análisis de seguridad independiente.
- Fuzzing, property-based testing y fault injection prolongado.
- mTLS, certificados de servidor con SAN, rotación/revocación y gestión de secretos.
- HSM/KMS para claves de CA/validadores, control de acceso y respaldos.
- Pruebas físicas entre instituciones en redes reales.
- Observabilidad, alertas, rate limits, hardening, procedimientos de incidentes y recuperación.
- Gobernanza de membresía, política de identidad, privacidad y revisión legal.
