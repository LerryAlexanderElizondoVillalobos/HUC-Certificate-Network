# Seguridad del SDK HUC Direct 0.8

## Modelo de confianza

El verificador confía en el pin SHA-256 externo del Trust Anchor. Ese ancla fija la CA, la clave pública de emisor y la política. Dentro del paquete se verifican X.509, HUC-CC, State Attestation y sus vínculos de hash.

## Límites críticos

1. **Centralización del estado:** el emisor mantiene el ledger y firma el estado. La arquitectura no pretende que sea consenso descentralizado.
2. **Frescura:** un paquete `ACTIVE` puede ser anterior a una revocación nueva. El TTL y `INDETERMINATE` reducen el riesgo; aplicaciones críticas deben exigir estado muy reciente o consulta directa al emisor.
3. **Identidad:** una CSR prueba posesión de clave, no identidad civil. El emisor debe integrar RA/KYC o proceso institucional según la credencial.
4. **Challenge-response:** prueba posesión de clave privada; no prueba por sí misma que la persona sea quien declara ni que tenga permiso para una acción.
5. **Replay store:** el nonce debe consumirse de manera atómica en un almacenamiento persistente compartido por todos los verificadores de una misma audiencia.
6. **Llaves:** el ejemplo Python almacena PEM sin cifrar; producción requiere HSM/KMS. Android usa Android Keystore, sujeto a capacidades y validación de cada fabricante.
7. **API:** no exponer Uvicorn directamente; usar HTTPS/mTLS, gateway, autenticación, autorización, límites, auditoría y protección de secretos.
8. **Transporte directo:** QR/NFC/Bluetooth son medios, no seguridad. El bundle es público; cualquier dato personal debe minimizarse y el transporte debe protegerse según la política de privacidad.
9. **Canonicalización:** perfil JSON restringido; se necesita RFC 8785/JCS interoperable y vectores cruzados antes de producción multi-lenguaje.
10. **Interoperabilidad PKI:** no hay OCSP/CRL; X.509 tradicional no verá automáticamente un cambio de estado HUC.

No usar este SDK de laboratorio como CA pública ni para TLS público, identidad legal, acceso crítico o certificados sujetos a regulación sin auditoría criptográfica, legal y de cumplimiento.
