# LAEV HUC 0.8 — Plan de prueba en cuatro dispositivos físicos

## 1. Alcance y estado

Este procedimiento permite probar cuatro validadores HUC en cuatro equipos físicos distintos: laptops, servidores o teléfonos Android con Termux. Cada institución conserva su clave privada HUC y ejecuta su propio proceso de validación.

**Estado de ejecución:** el paquete 0.8 incluye una prueba automatizada con cuatro procesos Python independientes y TLS sobre TCP loopback en un mismo host. La prueba entre cuatro dispositivos físicos y redes institucionales reales todavía no se ha ejecutado. Este documento es una guía de aceptación, no una afirmación de que ese ensayo ya pasó.

## 2. Topología de prueba

Ejemplo de una LAN privada o VPN administrada:

| Nodo | Dirección de ejemplo | Puerto TCP |
|---|---|---:|
| HUC-A | 10.20.0.11 | 8701 |
| HUC-B | 10.20.0.12 | 8701 |
| HUC-C | 10.20.0.13 | 8701 |
| HUC-D | 10.20.0.14 | 8701 |

Requisitos:

- Cuatro equipos distintos, con conectividad IP entre ellos.
- Python 3.10+.
- Proyecto HUC 0.8.0 idéntico en los cuatro dispositivos.
- Firewall que permita TCP/8701 solo entre los cuatro nodos.
- Hora del sistema razonablemente sincronizada.
- Certificados TLS de servidor con SAN que coincida con la IP/DNS anunciada.
- CA TLS pública distribuida por canal autenticado; su clave privada de firma se conserva fuera de los nodos.
- Cada nodo genera y conserva su propia clave privada Ed25519 HUC.

No abras el puerto a Internet pública durante esta prueba. Utiliza una LAN privada o VPN con reglas de firewall explícitas.

## 3. Instalar el software

En cada equipo, descomprime el proyecto y ejecuta:

```bash
python -m pip install -r requirements.txt
python --version
```

En Android/Termux:

```bash
pkg update
pkg install python openssl unzip
python -m pip install -r requirements.txt
```

## 4. Crear identidades HUC independientes

Cada equipo ejecuta su propio comando. Ejemplo en HUC-A:

```bash
python huc_replicated.py node-init --id HUC-A --out-dir ./node-A
```

En los otros equipos cambia el identificador y carpeta: `HUC-B`, `HUC-C` y `HUC-D`.

Cada equipo conserva `node-private.pem` localmente. Comparte exclusivamente `node-public.json`. Nunca copies la clave privada de un nodo a otro ni al coordinador de configuración.

Reúne los cuatro descriptores públicos mediante un canal autenticado.

## 5. Preparar X.509 y HUC-CC con autoridades independientes (perfil PKI)

Esta fase prepara la credencial que los cuatro validadores revisarán antes de firmar PREPARE. Las claves HUC-CC de las autoridades emisoras son distintas de las claves BFT de los validadores, aunque ambas puedan pertenecer a las mismas instituciones.

### 5.1 Cada autoridad genera su propia clave HUC-CC

En tres dispositivos de autoridad:

```bash
python huc_federation.py authority-init \
  --id HUC-ISSUER-A \
  --out-dir ./authority-A
```

Repite con `HUC-ISSUER-B` y `HUC-ISSUER-C`. Cada institución conserva su `authority-private.pem` y entrega únicamente `authority-public.json` al operador de la CA/emisor.

### 5.2 Configurar emisor y política

En el dispositivo que administra la CA emisora, crea el workspace utilizando los descriptores públicos:

```bash
python huc.py init \
  --workspace ./issuer \
  --threshold 2 \
  --authority-public ./public/authority-A/authority-public.json \
                    ./public/authority-B/authority-public.json \
                    ./public/authority-C/authority-public.json
```

Anota el `trust_anchor_sha256` que devuelve el comando. Debe verificarse y compartirse por un canal independiente.

### 5.3 Enrolar cada autoridad sin transferir su clave privada

En el emisor, exporta un paquete público de enrolamiento por autoridad:

```bash
python huc_federation.py export-enrollment \
  --workspace ./issuer \
  --authority-id HUC-ISSUER-A \
  --output ./enrollment-A.zip \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA
```

Copia `enrollment-A.zip` al dispositivo A. Allí ejecuta:

```bash
python huc_federation.py enroll \
  --authority-dir ./authority-A \
  --package ./enrollment-A.zip \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA
```

Repite para B y C. Los paquetes de enrolamiento contienen material público; no incluyen la clave privada de la autoridad.

### 5.4 Emitir X.509 + HUC-CC con 2 de 3 autoridades

El titular genera su clave y CSR:

```bash
python huc.py request \
  --out-dir ./requests \
  --name "HUC Physical Device Test"
```

El comando devuelve la ruta exacta del `.csr.pem`; usa esa ruta como `CSR_PATH` en el siguiente comando. El emisor prepara una propuesta:

```bash
python huc_federation.py propose-issue \
  --workspace ./issuer \
  --csr CSR_PATH \
  --output ./issue-proposal.json
```

Distribuye la propuesta a las autoridades A, B y C por un canal autenticado. Cada autoridad revisa y firma desde su propio dispositivo:

```bash
python huc_federation.py approve \
  --authority-dir ./authority-A \
  --proposal ./issue-proposal.json \
  --output ./approval-A.json
```

Repite en B y C. Transfiere al emisor solo los archivos públicos de aprobación. Finaliza con dos o más aprobaciones:

```bash
python huc_federation.py finalize \
  --workspace ./issuer \
  --proposal ./issue-proposal.json \
  --approval ./approval-A.json \
  --approval ./approval-C.json \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA \
  --output-dir ./finalized
```

El resultado proporciona las rutas del X.509 y HUC-CC. El emisor conserva la clave privada de CA; el titular conserva la clave privada correspondiente al CSR; cada autoridad conserva su clave privada Ed25519. Calcula los hashes con el fragmento de Python de la sección 11 y usa las rutas devueltas por `finalize` en `--certificate` y `--consensus-certificate` al crear la propuesta BFT.

## 6. Crear el manifiesto de red

En el equipo de configuración, con los cuatro descriptores públicos:

```bash
python huc_replicated.py network-create \
  --validator-public ./public/HUC-A/node-public.json \
                    ./public/HUC-B/node-public.json \
                    ./public/HUC-C/node-public.json \
                    ./public/HUC-D/node-public.json \
  --fault-tolerance 1 \
  --ca-certificate ./issuer/ca_certificate.pem \
  --consensus-policy ./issuer/consensus_policy.json \
  --output ./network.json
```

Este perfil PKI fija en el manifiesto la CA emisora y la política HUC-CC. Todos los validadores deben recibir exactamente el mismo manifiesto y verificar su huella externa.

Copia `network.json` a los cuatro equipos. Fija el `network_sha256` reportado por el comando por un canal independiente y autenticado. No confíes en un manifiesto solo porque llegó de otro peer.

En cada equipo:

```bash
python huc_replicated.py join \
  --node-dir ./node-A \
  --network ./network.json \
  --network-sha256 HUELLA_SHA256_DE_NETWORK

python huc_bft.py init --node-dir ./node-A
```

Repite en B, C y D.

## 7. Crear el mapa P2P

En el equipo de configuración:

```bash
python huc_peer.py peer-map-create \
  --network ./network.json \
  --network-sha256 HUELLA_SHA256_DE_NETWORK \
  --endpoint HUC-A=10.20.0.11:8701 \
  --endpoint HUC-B=10.20.0.12:8701 \
  --endpoint HUC-C=10.20.0.13:8701 \
  --endpoint HUC-D=10.20.0.14:8701 \
  --output ./peer-map.json
```

Fija la huella de `peer-map.json` fuera del propio archivo. Cada nodo instala el mapa:

```bash
python huc_peer.py peer-map-install \
  --node-dir ./node-A \
  --peer-map ./peer-map.json \
  --peer-map-sha256 HUELLA_SHA256_DEL_PEER_MAP
```

Repite para cada directorio de nodo.

## 8. Crear certificados TLS de servidor

La prueba de red física debe usar TLS. El protocolo de mensajes HUC tiene además firmas Ed25519 de aplicación, pero esas firmas no cifran el tráfico.

Procedimiento recomendado:

1. Cada nodo genera localmente su clave privada TLS y un CSR.
2. Una CA TLS institucional valida y firma los CSRs.
3. Cada nodo recibe su certificado y la CA pública `network-ca.pem`.
4. La CA privada no se copia a los nodos.

Ejemplo ilustrativo para generar un certificado de servidor en un nodo (ajusta la IP y firma el CSR con la CA de laboratorio/organización):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out tls-server.key
openssl req -new -key tls-server.key -out tls-server.csr \
  -subj "/CN=10.20.0.11"
```

El certificado firmado debe contener extensiones equivalentes a:

```ini
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:10.20.0.11
```

La SAN debe coincidir exactamente con el host usado por el peer map. Si se anuncia un DNS, incluye `DNS:nombre-institucional` en lugar de usar solo CN. La CA que custodia `network-ca.key` puede firmar el CSR con:

```bash
openssl x509 -req -in tls-server.csr \
  -CA network-ca.pem -CAkey network-ca.key -CAcreateserial \
  -out tls-server.pem -days 365 -sha256 \
  -extfile tls-extensions.cnf
```

La clave `network-ca.key` debe permanecer en el entorno de la CA y nunca copiarse a los cuatro nodos.

## 9. Iniciar los servidores

En cada equipo, mantén el servidor activo. Ejemplo HUC-A:

```bash
python huc_peer.py serve \
  --node-dir ./node-A \
  --bind-host 0.0.0.0 \
  --port 8701 \
  --tls-cert ./tls/HUC-A.pem \
  --tls-key ./tls/HUC-A.key
```

B, C y D deben usar su propio nodo, certificado TLS y clave TLS.

`0.0.0.0` es la interfaz de escucha, no la dirección que se anuncia en el peer map. El peer map debe contener la IP privada real.

Configura el firewall para permitir TCP/8701 únicamente desde la subred de los cuatro validadores.

## 10. Comprobar conectividad autenticada

Desde cada nodo:

```bash
python huc_peer.py status \
  --node-dir ./node-A \
  --tls-ca ./tls/network-ca.pem
```

Los otros tres nodos deben responder `ONLINE`. Si TLS falla, revisa SAN, CA, reloj, endpoint y firewall. No desactives la validación TLS como solución.

## 11. Ejecutar una operación BFT

Usa el X.509 y HUC-CC generados en la sección 5. Copia al proponente únicamente los artefactos públicos. El manifiesto de red debe haberse creado con `--ca-certificate ./issuer/ca_certificate.pem` y `--consensus-policy ./issuer/consensus_policy.json`, de modo que todos los nodos tengan fijados los mismos materiales de confianza.

La huella X.509 debe ser SHA-256 del certificado DER; la huella HUC-CC debe ser SHA-256 del JSON canónico. Para calcularlas con el módulo del proyecto:

```bash
python - <<'PY'
import json, sys
import huc
from cryptography import x509
from pathlib import Path
cert = x509.load_pem_x509_certificate(Path("certificate.pem").read_bytes())
cc = json.loads(Path("consensus_certificate.json").read_text())
print("X509_DER_SHA256=" + huc.cert_hash(cert))
print("HUC_CC_CANONICAL_SHA256=" + huc.sha256(huc.canonical_json(cc)))
PY
```

Crea la propuesta en el nodo primario de la vista actual (en vista 0, el ID primario es el primero de la lista ordenada de validadores):

```bash
python huc_bft.py propose \
  --node-dir ./node-A \
  --action ISSUE \
  --certificate-sha256 X509_DER_SHA256 \
  --consensus-sha256 HUC_CC_CANONICAL_SHA256 \
  --certificate ./certificate.pem \
  --consensus-certificate ./consensus_certificate.json \
  --output ./proposal.json
```

Difunde las fases PRE-PREPARE, PREPARE, PREPARED y COMMIT:

```bash
python huc_bft_peer.py broadcast \
  --node-dir ./node-A \
  --proposal ./proposal.json \
  --output-commit ./commit-certificate.json \
  --tls-ca ./tls/network-ca.pem
```

Comprueba estado en cada dispositivo:

```bash
python huc_bft.py status --node-dir ./node-A
python huc_bft.py status --node-dir ./node-B
python huc_bft.py status --node-dir ./node-C
python huc_bft.py status --node-dir ./node-D
```

Los cuatro nodos deben mostrar la misma `sequence` y `head_hash`.

## 12. Probar caída del primario y recuperación

Para una prueba de recuperación preparada, detén el primario después de que al menos tres réplicas hayan persistido la evidencia preparada, pero antes de completar COMMIT.

En la nueva vista, el siguiente primario puede reunir los mensajes de cambio de vista:

```bash
python huc_bft_peer.py advance-view \
  --node-dir ./node-B \
  --output ./new-view.json \
  --reason primary-unreachable \
  --tls-ca ./tls/network-ca.pem
```

Si el certificado NEW_VIEW contiene un `PreparedCertificate` seleccionado, recupéralo:

```bash
python huc_bft_peer.py recover \
  --node-dir ./node-B \
  --output-commit ./recovered-commit.json \
  --tls-ca ./tls/network-ca.pem
```

Reinicia el nodo A y sincronízalo desde B:

```bash
python huc_bft_peer.py sync \
  --node-dir ./node-A \
  --peer-id HUC-B \
  --tls-ca ./tls/network-ca.pem
```

Compara las cuatro cabezas de estado. Si aparecen certificados prepared incompatibles, HUC debe detener el avance y preservar evidencia para análisis; no debe improvisar una selección.

## 13. Pruebas adversariales manuales

| Escenario | Acción | Resultado exigido |
|---|---|---|
| 1 nodo cae | Detener un nodo | Los 3 restantes pueden alcanzar quorum |
| 2 nodos aislados | Dejar solo 2 conectados | No se confirma ningún commit |
| Mensaje repetido | Reenviar una misma envoltura firmada | Rechazo anti-replay |
| Mensaje manipulado | Cambiar payload/firma | Rechazo criptográfico |
| Doble PREPARE | Intentar votar propuestas diferentes en mismo slot | Rechazo por bloqueo anti-equivocación |
| Commit antiguo | Reenviar certificado ya aplicado | Idempotencia o rechazo, nunca nueva secuencia |
| Estado rollback | Entregar paquete de estado anterior | Rechazo |
| ViewChange conflicting | Presentar prepared certificates contradictorios | Safety halt, sin commit divergente |
| Nodo desconocido | Mensaje de ID no inscrito | Rechazo de identidad |

Conserva los logs de los cuatro dispositivos y sus hashes. Ejecuta estas pruebas en una red aislada, nunca en una red de producción.

## 14. Criterios de aceptación del ensayo físico

- Cuatro dispositivos distintos y cuatro claves privadas HUC distintas.
- TLS validado desde cada equipo hacia los peers configurados.
- ISSUE confirmado por 3 de 4 y mismo `head_hash` en todos.
- Un fallo de primario con recuperación documentada.
- Sincronización de un nodo reiniciado sin rollback.
- Partición de 2/2 sin confirmación.
- Rechazo de replay, firma alterada y voto equivocado.
- Ninguna clave privada HUC o TLS compartida entre instituciones.

El acta de prueba debe documentar sistema operativo, Python, versiones del paquete, topología, latencia, pérdida de paquetes, secuencias, hashes finales y logs. Solo después de completar este procedimiento puede declararse superada la prueba en dispositivos físicos.
