# Changelog — LAEV HUC

## 0.8.0

- Motor BFT-inspired con PRE-PREPARE, PREPARE, PrepareCertificate, prepared-lock acknowledgement quorum, PreparedCertificate, COMMIT y CommitCertificate.
- Bloqueos persistentes anti-equivocación por vista/secuencia y por estado preparado.
- VIEW_CHANGE firmado con evidencia de preparación y NEW_VIEW con selección determinista del PreparedCertificate de mayor vista.
- Recuperación de operación preparada en la nueva vista.
- Exportación/sincronización de estado BFT con verificación de commits, certificados de vista, continuidad y prevención de rollback/fork.
- Orquestación P2P por TCP para fases de consenso, cambio de vista, recuperación y sincronización.
- Integración PKI: cada validador comprueba X.509 y HUC-CC antes de firmar PREPARE.
- Test TLS con cuatro procesos de servidor independientes en loopback.
- Pruebas de quórum, particiones, replay, firmas alteradas, equivocación, recuperación y sincronización.
- Serialización persistente de operaciones críticas de consenso y regresión de doble firma concurrente.
- Suite completa ampliada a 90 pruebas.

## 0.7.0

- TCP peer communication, P2P, view change conservador y membership federada.

## 0.6.0

- Estado replicado con quórum 2f+1, anti-equivocación y sincronización.

## 0.5.0

- Autoridades HUC-CC con claves independientes.

## 0.4.0

- Certificado complementario HUC-CC y validación conjunta X.509 + HUC-CC + UTXO.
