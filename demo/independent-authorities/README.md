# LAEV HUC 0.5 — demostración de autoridades independientes

Esta carpeta contiene evidencia pública de un flujo completo con tres autoridades cuyas claves privadas se generaron en tres directorios/dispositivos temporales distintos. Las claves privadas se eliminaron al terminar y no están incluidas en estos archivos.

**Huella SHA-256 del ancla:** `8c94b15f1ebd0f72a8f27c0e6c7c189db2aca32925253dc27c37c2f38adb2ef3`

## Qué contiene

- `public/`: tres descriptores públicos independientes.
- `enrollment/`: paquetes de enrolamiento, sin claves privadas.
- `proposals/`: propuestas de emisión y revocación que se sometieron a firma.
- `approvals/`: aprobaciones firmadas desde tres almacenes privados separados (A+C para emitir, B+C para revocar).
- `state-sync/`: paquetes públicos de sincronización tras cada transición.
- `verification/active-certificate.zip`: certificado y evidencia válidos antes de revocar.
- `verification/revoked-certificate.zip`: mismo certificado con estado revocado.
- `public-workspace/`: archivos públicos del coordinador, sin claves privadas.
- `verification-results.json`: resultado esperado y observado.

## Comprobar los paquetes

Desde la raíz del proyecto:

```bash
PIN="$(cat demo/independent-authorities/trust-anchor.sha256)"
python huc.py verify-bundle --bundle demo/independent-authorities/verification/active-certificate.zip --trust-anchor-sha256 "$PIN"
python huc.py verify-bundle --bundle demo/independent-authorities/verification/revoked-certificate.zip --trust-anchor-sha256 "$PIN"
```

El paquete activo debe resultar `hybrid_valid: true`. El revocado debe quedar `package_verified: true`, pero `hybrid_valid: false` y `utxo_status: REVOKED`.

## Límite de la demostración

Los tres directorios simulan tres dispositivos independientes en una prueba reproducible. Para una prueba institucional real, cada entidad debe ejecutar `authority-init` en su propio dispositivo/servidor y transferir únicamente su descriptor público, propuestas, aprobaciones y paquetes públicos de estado. El coordinador todavía serializa el ledger; esto demuestra custodia independiente y quórum de autorización 2-de-3, no consenso BFT completo.
