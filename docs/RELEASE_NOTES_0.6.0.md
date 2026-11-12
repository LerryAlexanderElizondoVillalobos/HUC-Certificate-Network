# LAEV HUC 0.6.0 — Release notes

La versión 0.6 incorpora HUC-RSP, un mecanismo leaderless de estado replicado con certificado de quórum. Ya no existe un coordinador permanente con autoridad exclusiva para decidir el orden de las transiciones.

Para el perfil inicial se usan cuatro nodos independientes y tres firmas por commit. Cada nodo guarda su clave privada, valida propuesta/evidencia, registra un solo voto por slot y aplica commits que incluyen un quórum válido.

La demo ejecutada produjo tres commits (ISSUE, RENEW y REVOKE) y comprobó que las cuatro réplicas acabaron con el mismo hash de estado. Un nodo fue dejado sin aplicar el primer commit y se sincronizó posteriormente desde otro par.

No se incluye ninguna clave privada en la demostración pública.

**No confundir con BFT completo:** la versión 0.6 prioriza seguridad y se detiene ante un conflicto 2/2; no implementa view-change ni recuperación automática. El transporte usa paquetes firmados, no P2P automático.
