# LAEV HUC 0.7 — paquete de demostración pública

Este ZIP contiene solo los artefactos públicos generados por la demostración integrada de HUC 0.7. No incluye claves privadas, almacenes privados de CA ni bóvedas de los validadores.

## Escenarios incluidos

- Emisión de certificado X.509 + HUC-CC.
- Propuesta y commit ISSUE por TCP P2P.
- Certificado de View Change que cambia el proponente HUC-A → HUC-B.
- Renovación del certificado.
- Propuesta y certificado de membresía para sustituir HUC-A por HUC-E.
- Distribución P2P del paquete de membresía a los nodos retenidos HUC-C y HUC-D.
- Handoff de checkpoint a la época 1.
- Revocación del certificado renovado en la nueva membresía.
- Estado final de B/C/D/E con la misma secuencia y la misma cabeza de estado.

## Archivos relevantes

- `scenario-results.json`: resumen de las pruebas integradas.
- `membership-package.json`: certificado y checkpoint de membresía.
- `view-change-certificate.json`: certificado de cambio de vista.
- `commit-issue.json`, `commit-renew.json`, `commit-revoke.json`: commits replicados.
- `certificate-issued.pem`, `certificate-renewed.pem`: X.509 públicos.
- `consensus-issued.json`, `consensus-renewed.json`: HUC-CC públicos.
- `network-epoch0.json`, `network-epoch1.json`: manifiestos públicos.
- `peer-map-epoch0.json`, `peer-map-epoch1.json`: endpoints de la simulación loopback.
- `PUBLIC_ARTIFACTS_MANIFEST.json`: tamaño y SHA-256 de cada artefacto.

## Importante

La simulación de transporte fue realizada sobre TCP loopback, no sobre Internet ni entre cuatro organizaciones físicas. Los endpoint IP/puerto son ilustrativos. El paquete permite inspeccionar las evidencias públicas; no incluye las claves necesarias para hacerse pasar por las autoridades ni para generar nuevas firmas.
