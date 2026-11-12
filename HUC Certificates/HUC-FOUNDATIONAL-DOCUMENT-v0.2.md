# HUC — UTXO-Based Certificates

## Integrated Foundational Document

**Architecture, Principles, Philosophy, and Conceptual Specification**

**Version:** 0.2  
**Status:** Foundational Architectural Proposal  
**Author:** LAEV  
**Project Name:** HUC — UTXO-Based Certificates

---

## 1. Introduction

HUC is a worldwide certification infrastructure natively designed around the UTXO (*Unspent Transaction Output*) model.

Its purpose is to enable the creation, configuration, issuance, verification, communication, and administration of certificates through a structure in which each certificate has a committed configuration, its own identity, a verifiable history, and a lifecycle governed by previously established rules.

HUC is not a system for creating conventional documents and subsequently adding a hash or recording a digital fingerprint on a blockchain. The UTXO infrastructure is the structural foundation of certificates: it determines how their operation is configured, how their states are represented, and how their transitions are recorded.

The proposal aims to provide an infrastructure adaptable to multiple identification, accreditation, representation, recognition, and verification needs, without being limited to a particular institution, jurisdiction, document format, or certificate category.

HUC covers both individual certificates and certificates intended to represent relationships, groups, organizations, institutions, entities, and other identity structures.

The architecture also provides optional external stamping mechanisms to expand the independent verifiability of specific certificate operations.

---

## 2. Fundamental Nature of HUC

### 2.1. Worldwide Infrastructure

HUC is conceived as a worldwide infrastructure.

Its use does not depend on membership in any particular country, government, company, organization, or institution.

Each certificate may establish its own geographic, legal, institutional, or relational scope of application according to its configuration.

HUC's worldwide scope does not mean that every certificate automatically receives universal legal recognition. Legal validity, institutional recognition, and legal effects depend on the configured rules, the evidence provided, and any mandatory laws that may apply.

### 2.2. Native UTXO Infrastructure

HUC uses the UTXO model as the structural foundation for representing certificate configurations, states, operations, and transitions.

Each valid operation consumes a previously existing output and produces new outputs according to the infrastructure's rules.

The purpose is to prevent historical records from being silently modified and to make state changes identifiable and verifiable.

The UTXO infrastructure is not merely a mechanism for storing hashes. It is part of the certificate's operating logic.

HUC may be implemented on its own UTXO infrastructure or on one compatible with an existing network, provided that the security, integrity, and operational rules defined by the protocol are respected.

### 2.3. Native Configuration

Each certificate may establish its own operating conditions.

Configurable parameters include:

- The identity and identification intended to be certified.
- The nature of the subject, entity, or organization.
- Issuer, holder, beneficiary, and participants.
- Members, representatives, witnesses, and verifiers.
- Roles, responsibilities, and powers.
- Geographic, legal, and institutional scope.
- Evidence and verification requirements.
- Issuance, validity, and use conditions.
- Communication and information-exchange rules.
- Data-packet size, quantity, and format.
- Privacy and access conditions.
- Revocation, discard, and replacement rules.
- Stamping and external anchoring conditions.

This configuration allows each certificate to be adapted to its purpose without requiring all certificates to use an identical structure.

### 2.4. One-Time and Immutable Configuration

The fundamental configuration of each certificate is committed through a one-time UTXO operation.

Once the configuration operation has been executed and confirmed, its original parameters are cryptographically committed and cannot be edited, replaced, or reused as though they were a new configuration.

This establishes a fundamental rule:

**A misconfigured certificate is not corrected by modifying its original configuration; it is discarded and a new one is generated.**

The configuration may contain references to documents, evidence, and external data. Configuration immutability means that its original commitments and rules cannot be altered without leaving evidence of a new operation.

Subsequent transitions permitted by the protocol do not constitute a retroactive modification of the configuration.

---

## 3. Certificate Families: Identities and Identification

### 3.1. Foundation of Certificate Families

HUC certificate families are organized according to the identities, identification methods, subjects, entities, and relationships intended to be represented, certified, or verified.

Terms such as individual certificate, couple certificate, family certificate, or group certificate are illustrative examples of possible modalities. They do not constitute a closed classification or limit HUC's scope.

The intention is to develop an infrastructure capable of offering certificates according to different forms of identity and identification, including human, organizational, institutional, legal, digital, and other forms.

Possible applications include:

- Individuals.
- Couples and personal relationships.
- Families and family groups.
- Groups and communities.
- Associations and organizations.
- Companies and commercial entities.
- Public and private institutions.
- Government entities.
- Territorial organizations.
- Legal entities.
- Educational and professional entities.
- Digital and organizational identities.
- Contractual and commercial relationships.
- Service providers.
- Other structures or combinations of identity and identification.

This list is open-ended, illustrative, and non-exhaustive.

### 3.2. Identity and Identification

Each certificate family may define what identity and identification mean within its application context.

The configuration may establish:

- The nature of the identity.
- The type of identifier used.
- The subject or entity represented.
- The number of members.
- Relationships among participants.
- Roles, responsibilities, and representatives.
- Required evidence.
- Authorities or sources of recognition.
- Witnesses and verifiers.
- Applicable geographic or legal scope.

HUC will not depend on a single document, registry, or identification system.

It may recognize different identification sources and accreditation mechanisms, provided they satisfy the verification rules defined for the certificate.

It is important to distinguish between recording a declared identity and proving that the identity actually corresponds to a real person or entity. The latter requires evidence and validation mechanisms appropriate to each case.

### 3.3. Identity, Relationship, and Territory

The architecture must keep three concepts separate:

**Identity:** who or what is represented by the certificate.

**Relationship:** what connection, status, participation, or responsibility exists among the represented subjects or entities.

**Territory:** the geographic, legal, institutional, or administrative scope in which the certificate is intended to be applied or recognized.

These elements may be related within a single configuration, but they must not be conflated.

For example, a certificate may represent an individual's identity, certify that person's relationship with an organization, and establish a specific territorial scope for its use.

### 3.4. Extensible Certificate Families

Certificate families will not be a fixed and immutable list.

New modalities and combinations may be developed as identification, representation, and verification needs arise.

Adding new certificate families must not require retroactively modifying existing certificates or altering their original configurations.

**Fundamental principle: HUC does not merely classify human relationships; it provides a configurable infrastructure for representing and verifying identities, identification methods, subjects, entities, and their relationships.**

---

## 4. Members, Participants, Witnesses, and Verifiers

Each certificate may define its own members and participants according to its purpose.

Not all certificates require the same number of people, entities, or roles.

The configuration may include:

**Issuer:** the entity or person responsible for generating the certificate under the established rules.

**Holder:** the subject or entity to which the certificate belongs.

**Beneficiary:** the person or entity receiving a right, recognition, or benefit associated with the certificate.

**Participants:** subjects involved in the represented relationship or activity.

**Representatives:** subjects authorized to act on behalf of others under the established conditions.

**Witnesses:** participants who attest that they observed, witnessed, or became aware of specific facts, statements, or operations. Their participation does not automatically mean that they guarantee the absolute truth of all certificate content.

**Verifiers:** participants or entities responsible for checking requirements, evidence, signatures, rules, and certificate conditions.

Witnesses and verifiers perform different functions. A certificate may include both roles, only one of them, or neither.

It may also establish minimum, maximum, or specific numbers of participants, as well as conditions governing independence, replacement, authorization, and the scope of their functions.

---

## 5. Native Communication and Data Packets

Communication is part of HUC's functional architecture.

A certificate may provide configurable mechanisms for exchanging information, evidence, statements, documents, and acknowledgments among its participants.

The configuration may establish:

- Maximum size of each data packet.
- Maximum or permitted number of packets.
- Accepted formats.
- Individual identifiers.
- Transmission sequence.
- References between packets.
- Integrity hashes.
- Encryption and access conditions.
- Sender and recipient identification.
- Receipt acknowledgments.
- Retention rules.
- Access and verification conditions.

Packets may contain complete documents, fragments of information, or references to external content.

It is not mandatory to store every document within the UTXO infrastructure. Private data may be kept encrypted in external systems, while HUC records the cryptographic commitments, references, and operations needed to verify its integrity.

The architecture must make it possible to verify whether a packet matches its registered commitment without requiring its contents to be publicly accessible.

---

## 6. Certificate Lifecycle

Each certificate will have an identifiable and verifiable lifecycle.

Its operation must distinguish initial configuration, issuance, use, possible stamping operations, and termination.

### 6.1. Configuration

The certificate's parameters, identities, participants, rules, and conditions are defined.

The configuration is committed through a one-time UTXO operation.

### 6.2. Issuance

The creation of the certificate is recorded according to its committed configuration.

Issuance must make it possible to identify the certificate, its origin, its conditions, and its cryptographic references.

### 6.3. Activation

The certificate becomes operational when it satisfies the issuance and activation conditions that have been established.

A certificate may be active without having been externally stamped.

### 6.4. Subsequent Operations

The certificate may record operations authorized by its configuration, including communications, evidence submissions, verifications, and state changes.

These operations become part of its history. They must not be confused with editing the original configuration.

### 6.5. Discard

When a configuration error or another condition prevents the certificate from being used correctly, a discard operation is executed.

Discard consumes the corresponding UTXO state and records a terminal condition that prevents the certificate from continuing to be used as though it were valid and operational.

The previous history remains verifiable.

To replace it, a new certificate must be generated. The new certificate may include a reference to the discarded certificate.

### 6.6. Revocation

Revocation is distinct from discard.

Discard addresses an error or inability to use the certificate, particularly one related to its initial configuration.

Revocation addresses the loss of authorization, recognition, or validity of a certificate that may have been valid at its origin.

The conditions and powers governing revocation must be defined in the corresponding configuration.

### 6.7. Replacement

A new certificate may functionally replace an earlier one without modifying it.

The relationship between them will be recorded through references that identify which certificate was discarded, revoked, or replaced.

---

## 7. Geographic, Legal, and Institutional Configuration

HUC allows the application scope of each certificate to be configured.

Possibilities include, but are not limited to:

**Geographic:** worldwide, continental, international, national, regional, provincial, municipal, city, district, community, and residential.

**Institutional:** governmental, institutional, corporate, educational, professional, organizational, and contractual.

**Personal and relational:** individual, family, group, associative, commercial, and other relationships among subjects.

A certificate may operate without specifying a particular territory.

The absence of a configured territory means that no default jurisdiction has been fixed within the certificate's configuration. It does not mean that the certificate is exempt from mandatory laws that may apply.

Where appropriate, specific laws, jurisdictions, authorities, requirements, and territorial limits may be established.

---

## 8. External Stamp

### 8.1. Nature of the Stamp

The stamp is a voluntary operation that expands the available technological evidence.

It is not a general requirement to create, issue, activate, maintain, use, or verify an HUC certificate.

A certificate may exist and operate under its rules without undergoing a stamping operation.

The stamp does not purchase the certificate's validity, create its identity, grant authority to its issuer, or automatically make its contents true.

Its purpose is to incorporate independent and publicly verifiable external evidence of an operation associated with the certificate.

### 8.2. Philosophical Dimension

The stamp represents a voluntary decision to assume technological responsibility and facilitate external verification of a statement, commitment, or operation.

It is a decision to make evidence externally verifiable, not an obligation imposed on every certificate.

### 8.3. Theoretical Dimension

The stamp adds a second evidence infrastructure.

HUC maintains its own UTXO-based certification logic and, when stamping is used, incorporates a verifiable reference to an operation performed on an external infrastructure.

This makes it possible to compare certificate information against an independent source.

### 8.4. Symbolic Dimension

The stamp represents a commitment to leave external evidence that third parties can verify.

Its symbolic function must not be confused with an absolute guarantee of truth or legal recognition.

### 8.5. Technical Dimension

The stamping operation may be executed through an external transaction containing:

- A cryptographic commitment associated with the certificate.
- A data item inserted through OP_RETURN, where supported by the network being used.
- A transfer of a specified amount of sats to a configured destination address.
- Verifiable references to the transaction and payment result.

The economic transfer and the OP_RETURN data are different elements of the transaction.

OP_RETURN contains the commitment or reference data and does not constitute a spendable UTXO output.

The output receiving the sats is a separate payment output and, where applicable, represents the UTXO that can be identified through its TXID and output index.

For this reason, the `stamp_payment_outpoint` reference must identify the payment output, not the OP_RETURN output index.

### 8.6. Economic Dimension

The stamp may involve a verifiable economic transfer.

That transfer must not automatically be confused with an issuance fee, tax, donation, or price for the certificate's validity.

The economic meaning of the operation must be declared in the configuration.

The purpose is to record a voluntary and verifiable economic act associated with the stamping operation.

### 8.7. Technological Dimension

The stamp allows a third party to verify a transaction and its cryptographic commitment using the corresponding external infrastructure.

Verification must not depend exclusively on the certificate issuer's private records.

When a public network is used, verification may include the transaction identifier, outputs, amounts, addresses, confirmations, and established inclusion conditions.

---

## 9. Stamp Economics

### 9.1. Reference Amount

A reference policy is proposed: a minimum equivalent to USD 10 in sats for a stamping operation.

This amount is a proposed economic parameter for the stamp, not a general requirement for the existence or validity of an HUC certificate.

The calculation will use a BTC-to-USD price quotation:

`MINIMUM_SATS = ceil((10 × 100000000) / BTC_USD_PRICE)`

The pricing policy must specify:

- Price sources used.
- Aggregation method.
- Time of quotation.
- Reference time window.
- Rounding criterion.
- Treatment of differences between sources.
- Procedure when price data is unavailable.

Using multiple independent sources and a publicly defined aggregation method, such as the median of valid quotations, is recommended.

There is no universal official BTC price. Therefore, the calculation mechanism must be transparent and reproducible.

### 9.2. Default Destination Address

The configuration may establish a default destination address associated with the certificate's official repository or the project responsible for its infrastructure.

This address will be committed as part of the configuration and cannot be retroactively changed.

### 9.3. Alternative Address

Before the configuration is committed, an alternative destination address may be selected.

The alternative may belong to the issuer, certificate creator, holder, developer, company, institution, government, or another declared entity.

The default address must remain preserved in the configuration record.

The alternative address will be stored in a separate field and identified as the effective destination when used.

If no alternative is configured, the default address will be used.

### 9.4. Self-Receipt

The person or entity generating the certificate may use an address they control as the recipient of the transfer.

Self-receipt does not constitute a net economic contribution to a third party, although it still produces a verifiable transfer and requires payment of the network fee.

The architecture must reflect this condition without assigning it a different economic meaning from what it actually represents.

### 9.5. Separation Between Payment and Fee

The amount transferred to the recipient must be distinguished from the mining fee required to transmit and confirm the operation.

The amount allocated to the stamp must not be confused with the transaction-processing cost.

A payment above the minimum is permitted, but it does not automatically grant greater validity, authority, rights, or privileges over the certificate.

### 9.6. Meaning of the Transfer

The payment represents an economic operation voluntarily associated with the stamping act.

It may be interpreted as a commitment and a verifiable manifestation of technological responsibility toward the declared recipient.

It must not be presented as a universal commercial obligation or as a necessary condition for recognizing the existence of an HUC certificate.

---

## 10. Cryptographic Sealing and Stamping References

The architecture must avoid circular dependencies between certificate hashes and the transaction containing the stamping commitment.

For this purpose, the following elements are kept separate:

**`configuration_hash`:** cryptographic commitment to the certificate's original configuration.

**`stamp_commitment_hash`:** cryptographic commitment prepared before constructing the external transaction. This is the data that may be inserted into OP_RETURN.

**`transaction_id`:** identifier of the external transaction containing the commitment.

**`stamp_payment_outpoint`:** specific reference to the payment output, identified by TXID and `vout`.

**`sealed_certificate_hash`:** cryptographic closing commitment calculated after incorporating the final stamping-operation references into the certificate.

This procedure avoids requiring a transaction to contain a final hash that itself depends on that same transaction.

The logical sequence is:

1. The certificate is configured and committed.
2. The stamping commitment is generated.
3. The external transaction is constructed and broadcast.
4. The transaction and its payment output are checked.
5. The confirmation conditions are verified.
6. The external references are incorporated into the certificate record.
7. The closing hash is calculated.

If the `sealed_certificate_hash` is to be recorded subsequently on the same external network, a second anchoring operation will be required because that hash is calculated after the first transaction.

### 10.1. Confirmations

Broadcasting a transaction is not equivalent to confirmation.

The certificate must distinguish between a transaction that has been broadcast, one that has been observed on the network, and one that has been confirmed according to the established policy.

The minimum number of confirmations will be a configurable parameter.

### 10.2. Network Reorganizations

The architecture must account for possible reorganizations of the external chain.

If a transaction loses its inclusion in the main chain, the stamping status must be updated according to the verification rules.

Previous history will not be deleted. References to events and state changes will be preserved.

### 10.3. What the Stamp Proves

A properly verified stamp may prove the existence of a transaction, its inclusion under the established conditions, the registered cryptographic commitment, and an associated economic transfer.

By itself, it does not prove:

- That the certificate's contents are true.
- That a person's real-world identity has been verified.
- That the issuer has legal authority.
- That an institution recognizes the certificate.
- That the declared events actually occurred.

These conditions require their own identification, evidence, and validation mechanisms.

---

## 11. Certificate States

The following states are proposed:

**CONFIGURED:** initial configuration committed.

**ISSUED:** certificate issued according to the established conditions.

**ACTIVE:** certificate enabled for use.

**SEAL_PENDING:** stamping operation broadcast or awaiting verification.

**FINAL_SEALED:** stamp verified according to the configured policy.

**DISCARDED:** certificate discarded through a terminal operation.

**REVOKED:** certificate revoked under the applicable rules.

**SUPERSEDED:** certificate replaced by another certificate.

The `FINAL_SEALED` state represents completion of the stamping procedure, not a higher category of legal validity.

An `ACTIVE` certificate may operate without reaching `FINAL_SEALED`.

The absence of a stamp does not, by itself, constitute a deficiency, error, or loss of certificate validity.

Transitions between states must be executed through operations permitted by the protocol and represented in the UTXO history.

---

## 12. Privacy and Security

Verifiability must not require the indiscriminate publication of personal data, private documents, or sensitive information.

HUC must provide information-protection mechanisms from the initial configuration stage.

Its security principles include:

- Verifiable cryptographic commitments.
- Information integrity.
- Access control.
- Encryption of communications and private documents.
- Separation of public and private data.
- Operation records.
- Identification of authorized participants.
- Independent verification.
- Protection against retroactive modifications.
- Explicit management of revocations and discards.

Publishing a hash does not automatically make the associated information private. Data protection requires proper design of the committed content, access mechanisms, and metadata management.

The infrastructure must prevent public verification from revealing more information than necessary.

---

## 13. Functional Architecture

The HUC proposal may be organized into the following components:

### 13.1. Configuration Core

Contains the fundamental rules and unique parameters of each certificate.

Its cryptographic commitment defines the original operating conditions.

### 13.2. Identity and Representation

Manages the identification of subjects, entities, organizations, and relationships intended to be certified.

### 13.3. UTXO Engine

Manages outputs, spends, states, and permitted transitions.

It preserves traceability among certificate operations.

### 13.4. Communication Module

Manages data packets, evidence, messages, acknowledgments, and cryptographic references.

### 13.5. Verification Module

Makes it possible to check the conditions defined by the certificate, its evidence, participants, and transitions.

### 13.6. Stamping Module

Manages optional external operations, OP_RETURN commitments, payment transfers, and confirmation references.

### 13.7. History and Traceability

Makes it possible to reconstruct the certificate lifecycle and verify its operations from the original configuration to its current or terminal state.

---

## 14. Fundamental Principles

The HUC architecture is based on the following principles:

1. **Native UTXO:** the UTXO structure is part of the certificate's nature.
2. **One-time configuration:** each certificate commits to one original configuration for one-time use.
3. **Immutability:** the committed configuration cannot be modified retroactively.
4. **Irreversible discard:** a misconfigured certificate must be discarded and replaced with a new one.
5. **Open identity:** certificate families are organized around identities, identification methods, subjects, entities, and relationships.
6. **Extensibility:** certificate families do not form a closed classification.
7. **Configurability:** each certificate establishes rules according to its purpose.
8. **Territorial independence:** HUC does not impose a default jurisdiction.
9. **Traceability:** operations and transitions must be verifiable.
10. **Privacy:** verifiability does not require indiscriminate publication of data.
11. **Native communication:** information exchanges are part of the architecture.
12. **Distinct witness and verifier roles:** their functions must be clearly defined.
13. **Voluntary stamp:** external evidence expands verifiability but is not a general requirement.
14. **Separation of evidence:** the existence of a transaction does not, by itself, guarantee the truth of its contents.
15. **Verifiable replacement:** a new certificate may replace another without altering its history.

---

## 15. Essential Definition

**HUC is a worldwide certification infrastructure natively built on the UTXO model. It enables certificates to be generated, configured, issued, used, and verified through unique and immutable configurations, organized into open-ended families according to the identities, identification methods, subjects, entities, and relationships intended to be represented or certified.**

Each certificate establishes its own operating conditions, participants, evidence, scopes of application, communication rules, and verification mechanisms.

Its history is represented through verifiable operations and state transitions while preserving the integrity of the original configuration.

HUC allows voluntary external stamping mechanisms to be incorporated to expand the independence of technological evidence, without making the existence or general validity of a certificate depend on them.

---

## 16. Philosophical Statement

HUC begins with a fundamental idea: certification should not depend exclusively on documents, institutions, or centralized registries.

A certification infrastructure must make it possible for each certificate's rules to be explicit, verifiable, and committed from its origin.

Identity must not be limited to a document format, a human category, or an institutional structure.

Identification and representation needs are diverse and evolving. Therefore, the infrastructure must be able to adapt without compromising the integrity of certificates that have already been issued.

One-time configuration establishes responsibility for the original conditions. Discard prevents an error from being turned into a silent modification. Traceability preserves history. Verification makes operations auditable. The stamp adds independent external evidence when its use is chosen.

HUC proposes an infrastructure in which each certificate is created with its own rules, preserves its identity throughout its history, and can be verified without relying exclusively on trust in the issuer.

---

## 17. Pending Technical Specifications

This document establishes the conceptual and architectural foundations of HUC. Before definitive implementation, at least the following specifications must be developed:

1. Exact model of UTXO transactions and outputs.
2. Configuration and issuance data structure.
3. Certificate identification scheme.
4. Rules for consuming and generating UTXO states.
5. Cryptographic authorization conditions.
6. Management of private keys, representatives, and participants.
7. Witness and verifier model.
8. Communication formats and protocols.
9. Data-packet and evidence specifications.
10. Privacy and access-control policies.
11. Discard, revocation, and replacement rules.
12. Complete external stamping procedure.
13. Pricing policy and sats calculation.
14. Address and payment-output validation.
15. Confirmations and reorganization handling.
16. Commitment and hash formats.
17. Public query and verification interfaces.
18. Interoperability with different UTXO infrastructures.
19. Evidence retention and availability requirements.
20. Protocol governance and evolution model.

The technical specification must preserve the foundational principles established in this document and prevent implementation decisions from silently altering the model's nature.

---

**End of the HUC Integrated Foundational Document — Version 0.2.**
