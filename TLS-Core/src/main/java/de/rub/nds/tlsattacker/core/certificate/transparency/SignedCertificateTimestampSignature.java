/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLog;
import de.rub.nds.tlsattacker.core.constants.CertificateTransparencyLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;

public class SignedCertificateTimestampSignature {

    protected static final Logger LOGGER = LogManager.getLogger();

    private byte[] encodedSignature;
    private byte[] signature;
    private SignatureAndHashAlgorithm signatureAndhashAlgorithm;

    public byte[] getEncodedSignature() {
        return encodedSignature;
    }

    public void setEncodedSignature(byte[] encodedSignature) {
        this.encodedSignature = encodedSignature;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return signatureAndhashAlgorithm;
    }

    public void setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndhashAlgorithm) {
        this.signatureAndhashAlgorithm = signatureAndhashAlgorithm;
    }

    private boolean verifySignature(SignedCertificateTimestamp sct, CtLog ctLog) {
        try {
            Signature signature = Signature.getInstance(signatureAndhashAlgorithm.getJavaName());

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(ctLog.getPublicKey());
            KeyFactory keyFactory =
                    KeyFactory.getInstance(
                            signatureAndhashAlgorithm.getSignatureAlgorithm().getJavaName());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            signature.initVerify(publicKey);

            byte[] data = assembleSignatureData(sct);
            signature.update(data);
            return signature.verify(this.signature);

        } catch (Exception e) {
            LOGGER.warn("Unable to verify SCT signature", e);
        }

        return false;
    }

    private byte[] assembleSignatureData(SignedCertificateTimestamp sct)
            throws ParserException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // version
        outputStream.write(SignedCertificateTimestampVersion.encodeVersion(sct.getVersion()));

        // signature type
        byte signatureType =
                SignedCertificateTimestampSignatureType.encodeVersion(
                        SignedCertificateTimestampSignatureType.CERTIFICATE_TIMESTAMP);
        outputStream.write(signatureType);

        // timestamp
        byte[] timestamp = ArrayConverter.longToBytes(sct.getTimestamp(), Long.BYTES);
        outputStream.write(timestamp);

        // Append two-byte LogEntryType (0 = Cert; 1 = PreCert)
        outputStream.write(
                SignedCertificateTimestampEntryType.encodeVersion(sct.getLogEntryType()));

        byte[] encodedCertificate;
        if (SignedCertificateTimestampEntryType.X509ChainEntry == sct.getLogEntryType()) {
            // X.509 Certificate
            encodedCertificate = convertCertificateToDer(sct.getCertificate());
        } else {
            // PreCertificate
            encodedCertificate =
                    convertToPreCertificate(sct.getCertificate(), sct.getIssuerCertificate());
        }
        outputStream.write(encodedCertificate);

        byte[] extensions = sct.getExtensions();

        // Append two-byte extension length
        outputStream.write(
                ArrayConverter.intToBytes(
                        extensions.length, CertificateTransparencyLength.EXTENSION_LENGTH));

        // Append extension data
        outputStream.write(extensions);

        return outputStream.toByteArray();
    }

    /**
     * Converts an end-entity certificate into a precertificate used to verify precertificate SCT
     * signatures. See RFC 6962 Section 3.2 for more information on how to construct a
     * precertificate entry: <a href="https://tools.ietf.org/html/rfc6962#section-3.2">RFC 6962
     * Section 3.2</a>
     *
     * @param leafCertificate The leaf certificate
     * @param issuerCertificate The issuer certificate
     * @return Precertificate as DER-encoded byte[]
     */
    private byte[] convertToPreCertificate(
            Certificate leafCertificate, Certificate issuerCertificate) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // Compute SHA-256 hash of the certificate issuer's public key,
        // calculated over the DER encoding of the key
        // represented as SubjectPublicKeyInfo.
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedIssuerCertificate =
                    issuerCertificate.getSubjectPublicKeyInfo().getEncoded("DER");
            byte[] issuerKeyHash = digest.digest(encodedIssuerCertificate);
            outputStream.write(issuerKeyHash);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("SHA-256 is not supported on this platform", e);
        }

        TBSCertificate originalTbsCertificate = leafCertificate.getTBSCertificate();

        // Recreate the TBSCertificate without CT Poisoning extension and
        // without SCT Timestamp List extension. In case
        // the Precertificate was signed by a dedicated Precertificate Issuing
        // CA, modify the Authority Key Identifier
        // extension accordingly.
        V3TBSCertificateGenerator tbsCertificateGenerator = new V3TBSCertificateGenerator();
        tbsCertificateGenerator.setSerialNumber(originalTbsCertificate.getSerialNumber());
        tbsCertificateGenerator.setSignature(originalTbsCertificate.getSignature());
        tbsCertificateGenerator.setIssuer(originalTbsCertificate.getIssuer());
        tbsCertificateGenerator.setStartDate(originalTbsCertificate.getStartDate());
        tbsCertificateGenerator.setEndDate(originalTbsCertificate.getEndDate());
        tbsCertificateGenerator.setSubject(originalTbsCertificate.getSubject());
        tbsCertificateGenerator.setSubjectPublicKeyInfo(
                originalTbsCertificate.getSubjectPublicKeyInfo());
        tbsCertificateGenerator.setIssuerUniqueID(originalTbsCertificate.getIssuerUniqueId());
        tbsCertificateGenerator.setSubjectUniqueID(originalTbsCertificate.getSubjectUniqueId());

        // Copy all extensions except 'Precertificate Poison' and 'SCT List'
        // extension and recreate X.509 Extensions
        List<Extension> extensionList = new ArrayList<Extension>();
        Extensions extensions = originalTbsCertificate.getExtensions();
        for (ASN1ObjectIdentifier objectIdentifier : extensions.getExtensionOIDs()) {
            if (!ExtensionObjectIdentifier.PRECERTIFICATE_POISON.equals(objectIdentifier.getId())
                    && !ExtensionObjectIdentifier.SIGNED_CERTIFICATE_TIMESTAMP_LIST
                            .getOID()
                            .equals(objectIdentifier.getId())) {
                Extension extension = extensions.getExtension(objectIdentifier);
                extensionList.add(extension);
            }
        }

        tbsCertificateGenerator.setExtensions(
                new Extensions(extensionList.toArray(new Extension[] {})));
        TBSCertificate modifiedTbsCertificate = tbsCertificateGenerator.generateTBSCertificate();

        // Append DER encoded TBSCertificate
        outputStream.write(convertCertificateToDer(modifiedTbsCertificate));

        return outputStream.toByteArray();
    }

    private byte[] convertCertificateToDer(ASN1Object certificate) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[] encodedCertificate = certificate.getEncoded("DER");

        // Append three-byte certificate length
        outputStream.write(ArrayConverter.intToBytes(encodedCertificate.length, 3));

        // Append ASN.1 certificate
        outputStream.write(encodedCertificate);

        return outputStream.toByteArray();
    }

    public String toString(SignedCertificateTimestamp sct, CtLog ctLog) {
        StringBuilder sb = new StringBuilder();

        sb.append("\n Signature: ");
        sb.append(
                signatureAndhashAlgorithm.getSignatureAlgorithm()
                        + " with "
                        + signatureAndhashAlgorithm.getHashAlgorithm());
        if (ctLog != null) {
            boolean signatureValid = verifySignature(sct, ctLog);
            sb.append(signatureValid ? " (valid)" : " (invalid)");
        } else {
            sb.append(" (not tested)");
        }
        sb.append(ArrayConverter.bytesToHexString(signature).replaceAll("\\n", "\n    "));

        return sb.toString();
    }
}
