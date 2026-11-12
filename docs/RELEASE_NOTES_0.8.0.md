# LAEV HUC 0.8.0 — Release notes

## Objetivo

Formalizar e implementar una máquina de consenso BFT-inspired y recuperación de operaciones para el estado HUC sin blockchain ni criptomoneda.

## Incluido

1. PRE-PREPARE firmado por el primario de la vista.
2. PREPARE con votos únicos y PrepareCertificate de quórum.
3. Prepared lock persistente y PreparedCertificate con firmas de bloqueo.
4. COMMIT con CommitCertificate de quórum.
5. NEW_VIEW con ViewChange quorum y evidencia de las operaciones preparadas.
6. Reproposición de la operación preparada elegida por NEW_VIEW.
7. State export/sync con reproducción de commit ledger, validación de certificados de vista y anti-rollback.
8. Orquestación de fases por TCP entre peers y validación X.509/HUC-CC en cada validador.
9. Bloqueo persistente común para serializar validaciones y escrituras de PREPARE, prepared locks, COMMIT y VIEW CHANGE.
10. Prueba concurrente de propuestas conflictivas para comprobar que una réplica no firma dos PREPARE incompatibles en la misma posición.

## Perfil de consenso

Para cuatro nodos: n=3f+1, f=1, quorum=2f+1=3. Este perfil presupone como máximo un validador bizantino, claves seguras, persistencia durable y red con identidad autenticada. Si no existe quorum, no hay commit.

## Pruebas

Comando reproducible:

```bash
python -m unittest discover -s tests -v
```

Resultado del paquete: 90 pruebas aprobadas. Incluye una prueba de integración TLS con cuatro procesos independientes en un mismo host.

## No incluido / no afirmado

- No es PBFT formalmente verificado ni equivalente a una implementación de referencia auditada.
- No se ha ejecutado la prueba sobre cuatro dispositivos físicos ni sobre WAN/NAT real.
- No se ha realizado auditoría de seguridad de terceros, verificación formal, fuzzing exhaustivo ni prueba de carga.
- No se incluye mTLS obligatorio cliente-servidor, descubrimiento P2P automático, relays, NAT traversal, HSM/KMS ni operación de producción.

## Advertencia

Versión experimental de laboratorio. No usar para certificados de identidad legal, TLS público o servicios de producción sin revisión técnica, criptográfica, operacional y legal independiente.
