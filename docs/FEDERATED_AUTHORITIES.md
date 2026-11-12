# LAEV HUC 0.5 — autoridades independientes

## Qué cambia

En el perfil federado cada autoridad genera y conserva su propia clave Ed25519 en su dispositivo o servidor. El coordinador recibe únicamente descriptores públicos y archivos de aprobación firmados. Ninguna clave privada de autoridad se copia al workspace coordinador.

La aprobación usa tres firmas por autoridad:

1. Firma del identificador/hash de la propuesta completa.
2. Firma del payload exacto de transición UTXO.
3. Firma del payload exacto del certificado HUC-CC (solo emisión/renovación).

La firma de transición entra al ledger; la firma HUC-CC queda en el certificado complementario. El finalizador verifica el quórum con la política pública registrada.

## Flujo institucional real

### A. Cada institución crea su autoridad en su propio dispositivo

Ejecutar una vez, por separado en cada servidor o dispositivo institucional:

```bash
python huc_federation.py authority-init \
  --id INSTITUTION-A \
  --out-dir ./authority-a
```

En la segunda y tercera institución usar IDs distintos:

```bash
python huc_federation.py authority-init --id INSTITUTION-B --out-dir ./authority-b
python huc_federation.py authority-init --id INSTITUTION-C --out-dir ./authority-c
```

Cada ejecución crea:

- `authority-private.pem`: clave privada Ed25519, que permanece en ese dispositivo.
- `authority-public.json`: descriptor público que se entrega al coordinador.

**Solo se envía `authority-public.json`. Nunca enviar `authority-private.pem`.** La clave privada se crea en cada entorno, no en el coordinador.

### B. El coordinador inicializa HUC con las tres claves públicas

Reunir los tres descriptores públicos en una carpeta de recepción y ejecutar:

```bash
python huc.py init \
  --workspace ./huc-workspace \
  --threshold 2 \
  --authority-public ./public/authority-public-A.json \
                     ./public/authority-public-B.json \
                     ./public/authority-public-C.json
```

`--authority-public` hace que el workspace registre exclusivamente las claves públicas suministradas. No genera ni importa las claves privadas de las autoridades. La política y su huella quedan fijadas en `trust_anchor.json`.

Guardar `trust_anchor_sha256` fuera del workspace y distribuirla a las autoridades por un canal independiente del ZIP de enrolamiento.

### C. El coordinador prepara un paquete público para cada autoridad

```bash
python huc_federation.py export-enrollment \
  --workspace ./huc-workspace \
  --authority-id INSTITUTION-A \
  --output ./handoff/enroll-A.zip \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA
```

Repetir para B y C, cambiando ID y nombre del ZIP. Cada paquete contiene política, ancla, certificado público de CA, clave pública del registro y ledger actual. No contiene claves privadas.

### D. Cada autoridad se enrola localmente

En el dispositivo de la Institución A:

```bash
python huc_federation.py enroll \
  --authority-dir ./authority-a \
  --package ./enroll-A.zip \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA
```

Las autoridades B y C hacen lo mismo con sus propios directorios y paquetes. El enrolamiento comprueba que la clave privada local corresponde al descriptor público que aparece en la política y que la huella del ancla coincide con el valor obtenido fuera de banda.

### E. Preparar una emisión en el coordinador

El titular genera su clave y CSR localmente:

```bash
python huc.py request --out-dir ./holder --name "Titular de Prueba"
```

El coordinador prepara una propuesta, todavía sin registrar la transición:

```bash
python huc_federation.py propose-issue \
  --workspace ./huc-workspace \
  --csr ./holder/Titular_de_Prueba-FECHA.csr.pem \
  --days 365 \
  --output ./proposals/issue-001.json
```

Enviar `issue-001.json` a las tres autoridades. El archivo contiene el X.509 propuesto, el payload UTXO y el payload HUC-CC; no contiene claves privadas.

### F. Cada autoridad revisa y firma en su propio entorno

Institución A:

```bash
python huc_federation.py approve \
  --authority-dir ./authority-a \
  --proposal ./issue-001.json \
  --output ./approvals/issue-A.json
```

Instituciones B y C ejecutan el mismo comando desde sus propios directorios. Cada autoridad revisa la propuesta, verifica que su ledger local esté en el mismo checkpoint y firma con su propia clave privada.

La clave privada no viaja. Solo vuelve al coordinador el archivo `issue-A.json` firmado.

### G. El coordinador finaliza con el quórum

```bash
python huc_federation.py finalize \
  --workspace ./huc-workspace \
  --proposal ./issue-001.json \
  --approval ./approvals/issue-A.json \
  --approval ./approvals/issue-C.json \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA \
  --output-dir ./finalized
```

El coordinador verifica las firmas y permisos, comprueba el quórum 2-de-3 y vuelve a comprobar que el checkpoint no haya cambiado. Si otra transición avanzó el ledger, la propuesta antigua se rechaza y hay que crear otra.

El resultado incluye X.509, HUC-CC, outpoint UTXO y paquete público verificable.

### H. Sincronizar el estado público a las autoridades

Después de cada transición finalizada, el coordinador exporta el estado actualizado:

```bash
python huc_federation.py export-state \
  --workspace ./huc-workspace \
  --output ./handoff/state-002.zip \
  --trust-anchor-sha256 HUELLA_DEL_ANCLA
```

Cada institución importa el paquete:

```bash
python huc_federation.py sync \
  --authority-dir ./authority-a \
  --package ./state-002.zip
```

Repetir para B y C antes de que aprueben la siguiente transición. El comando `sync` verifica firmas, ancla y continuidad; rechaza rollback o una historia divergente.

### I. Renovar o revocar

Preparar renovación:

```bash
python huc_federation.py propose-renew \
  --workspace ./huc-workspace \
  --certificate ./huc-workspace/certificates/certificate-ANTERIOR.pem \
  --csr ./holder-renewal/nuevo.csr.pem \
  --output ./proposals/renew-001.json
```

Preparar revocación:

```bash
python huc_federation.py propose-revoke \
  --workspace ./huc-workspace \
  --certificate ./huc-workspace/certificates/certificate-ACTIVO.pem \
  --reason "key-compromise" \
  --output ./proposals/revoke-001.json
```

En ambos casos, las autoridades deben tener sincronizado el último ledger. Luego aprueban y el coordinador finaliza usando el mismo flujo `approve` + `finalize`.

## Reglas de independencia demostradas

- Tres claves privadas son generadas en tres directorios independientes.
- La política se construye a partir de tres descriptores públicos diferentes.
- El workspace del coordinador no contiene claves privadas de autoridad.
- Cada autoridad solo firma desde su propio directorio local.
- Una autoridad rechaza una propuesta preparada sobre un checkpoint que no conoce.
- El coordinador rechaza aprobaciones repetidas, inválidas o insuficientes.
- Una propuesta queda obsoleta después de que otra transición modifica el ledger.
- Una autoridad no puede firmar dos propuestas en conflicto para el mismo checkpoint mientras el bloqueo esté activo.
- El paquete de enrolamiento y sincronización solo contiene información pública.

## Qué significa y qué no significa

Este flujo demuestra **autorización criptográfica 2-de-3 con custodias separadas**, coordinación por propuestas y sincronización verificable de estado. No es todavía consenso BFT ni un ledger replicado en producción. El coordinador sigue serializando las transiciones y firma el ledger con su clave de registro; si el coordinador o esa clave se comprometen, puede detener o censurar operaciones. Las autoridades detectan propuestas obsoletas solo después de actualizar su checkpoint.

Para un consenso distribuido sin coordinador de confianza sería necesario implementar un protocolo BFT o un servicio de consenso replicado con reglas de quórum, líder, view-change, seguridad y recuperación. Eso no se debe afirmar basándose únicamente en tres firmas.

## Custodia de claves

Esta versión guarda claves Ed25519 sin cifrar en PEM para facilitar pruebas. Para producción, cada institución debe usar HSM/KMS o almacén protegido del sistema operativo, autorización por operador, respaldo y rotación. No copiar claves privadas a nubes compartidas ni al repositorio Git.

## Confirmación del operador

El comando `approve` es interactivo por defecto. Muestra operación, sujeto, hash del X.509, política, checkpoint, UTXO anterior/nuevo y vencimiento, y requiere que el operador escriba `APROBAR`. La opción `--yes` omite esa confirmación y debe reservarse para automatización controlada después de revisar previamente el contenido.

### Protección anti-equivocación

Cada autoridad registra localmente el `proposal_id` aprobado por checkpoint. Si recibe otra propuesta distinta para ese mismo checkpoint y la primera aún no expiró, rechaza firmarla. Cuando sincroniza un ledger que avanza, elimina los bloqueos correspondientes a checkpoints ya superados. Este control reduce la posibilidad de que una autoridad honesta contribuya a dos quórums incompatibles al mismo nivel, pero sigue siendo un control local: no sustituye consenso BFT, almacenamiento anti-rollback respaldado por hardware ni comunicación directa de votos entre autoridades.
