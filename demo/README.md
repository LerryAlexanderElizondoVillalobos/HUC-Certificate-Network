# Demostración integral HUC 0.7

## Ejecutar

Desde la raíz del proyecto:

```bash
python demo/run_huc07.py
```

Se crean temporalmente los nodos A/B/C/D y una nueva institución E. Cada nodo tiene una clave Ed25519 privada propia en un directorio diferente. Los servicios TCP se inician en `127.0.0.1` para que la demostración pueda ejecutarse localmente.

La secuencia es ISSUE → VIEW_CHANGE → RENEW → MEMBERSHIP_HANDOFF (A sale y E entra) → REVOKE.

La prueba de membresía recopila votos mediante mensajes P2P y envía el paquete certificado a los miembros retenidos. Los miembros existentes no tienen que intercambiar archivos de votos o de membresía manualmente. E recibe la invitación de incorporación mediante el paquete autenticado de sucesión, porque no es miembro de la red anterior.

Los artefactos públicos resultantes se escriben en `demo/huc07/public-artifacts/`. No se copian claves privadas. El resultado detallado es `scenario-results.json`.

## Resultado esperado

- ISSUE: COMMITTED, quorum de validadores alcanzado.
- VIEW_CHANGE: INSTALLED, nuevo proponente HUC-B.
- RENEW: COMMITTED.
- MEMBERSHIP_HANDOFF: ACTIVATED, HUC-A retirado y HUC-E agregado; epoch 1.
- REVOKE: COMMITTED.
- Réplicas B/C/D/E: misma secuencia y mismo hash de cabeza.

## Alcance de demostración

La red es TCP real entre procesos locales, pero todos se ejecutan en loopback. No demuestra conectividad sobre Internet, NAT, firewalls ni disponibilidad 24/7. Para un despliegue remoto configura TLS o VPN, endpoints accesibles, `peer-map` autenticado y certificados de servidor correctos.


## HUC 0.8

La versión 0.8 incorpora consenso BFT-inspired. Ejecuta `bash run_tests.sh` desde la raíz del proyecto para reproducir las 90 pruebas, incluida la integración TLS de cuatro procesos en loopback y la prueba concurrente de PRE-PREPARE conflictivo. La prueba en dispositivos físicos está descrita en `PHYSICAL_DEVICE_TEST.md` y todavía debe ejecutarse entre equipos reales.
