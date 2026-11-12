# LAEV HUC 0.7.0 — Release notes

## Alcance

HUC 0.7 elimina el intercambio manual de archivos en el flujo de laboratorio y agrega tres mecanismos:

1. **Peer Communication:** transporte TCP directo con sobres firmados por las claves Ed25519 de los validadores.
2. **View Change:** cambio de proponente aprobado por quórum y recuperación conservadora de una propuesta bloqueada.
3. **Membership Protocol:** cambio de comité con solicitud PoP del nuevo nodo, aprobación del comité previo, checkpoint, distribución P2P a nodos retenidos y activación de epoch.

## Demostración integral ejecutada

La demostración `demo/run_huc07.py` ejecuta servicios en cuatro endpoints TCP de loopback y realiza:

- ISSUE con cuatro respuestas de validadores;
- caída del proponente HUC-A y cambio de vista con tres mensajes firmados; HUC-B pasa a ser primario;
- RENEW desde HUC-B;
- reemplazo de HUC-A por HUC-E aprobado por el comité anterior; el paquete se distribuye por P2P a HUC-C y HUC-D y luego B/C/D activan la época; E entra con su clave propia;
- REVOKE con cuatro respuestas de validadores;
- comprobación de que B, C, D y E conservan la misma cabeza de estado, secuencia 3, certificado antiguo SUPERSEDED y certificado renovado REVOKED.

## Pruebas

Ejecutar `python -m unittest discover -s tests -v`. El número exacto de pruebas y sus resultados se guardan en `TEST_RESULTS_0.7.0.txt`.

## Sin blockchain ni comisiones

No hay bloques, minería, token, criptomoneda ni fee de protocolo. Los costes de servidor, VPN, certificados TLS y operación institucional siguen siendo responsabilidad de los participantes.

## Límites

El transporte se probó en loopback, no en Internet entre dispositivos físicos. View Change 0.7 es conservador y no implementa PBFT/HotStuff completo. El paquete de membresía del nuevo nodo requiere un canal de invitación autenticado, ya que dicho nodo todavía no pertenece al peer map anterior. Para redes no confiables debe habilitarse TLS o VPN; las firmas Ed25519 de aplicación no cifran el contenido.
