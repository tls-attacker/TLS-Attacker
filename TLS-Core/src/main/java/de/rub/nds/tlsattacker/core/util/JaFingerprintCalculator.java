/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.hash.HashCalculator;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JaFingerprintCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    private JaFingerprintCalculator() {}

    public static String getJa3sFingerprintString(ServerHelloMessage serverHelloMessage) {
        StringBuilder ja3StringBuilder = new StringBuilder();
        appendVersion(serverHelloMessage, ja3StringBuilder);
        appendSelectedCipherSuite(serverHelloMessage, ja3StringBuilder);
        appendExtensions(serverHelloMessage, ja3StringBuilder);
        // Remove the supperfluos , at the end
        ja3StringBuilder.deleteCharAt(ja3StringBuilder.length() - 1);
        return ja3StringBuilder.toString();
    }

    public static byte[] getJa3sFingerprintHash(ServerHelloMessage serverHelloMessage) {
        return HashCalculator.compute(
                getJa3sFingerprintString(serverHelloMessage).getBytes(), HashAlgorithm.MD5);
    }

    public static byte[] getJa3FingerprintHash(ClientHelloMessage clientHelloMessage) {
        return HashCalculator.compute(
                getJa3FingerprintString(clientHelloMessage).getBytes(), HashAlgorithm.MD5);
    }

    public static String getJa3FingerprintString(ClientHelloMessage clientHelloMessage) {
        StringBuilder ja3StringBuilder = new StringBuilder();
        appendVersion(clientHelloMessage, ja3StringBuilder);
        appendCipherSuites(clientHelloMessage, ja3StringBuilder);
        appendExtensions(clientHelloMessage, ja3StringBuilder);
        appendEllipticCurves(clientHelloMessage, ja3StringBuilder);
        appendPointFormats(clientHelloMessage, ja3StringBuilder);
        return ja3StringBuilder.toString();
    }

    /**
     * Custom version of JA3 for certificates. It uses cert count, issuer CN length, subject CN
     * length, publickey oid, signature algorithm oid
     *
     * @return
     */
    public static String getJa3CertFingerprintString(CertificateMessage certificateMessage) {
        StringBuilder ja3StringBuilder = new StringBuilder();
        appendCertificateCount(certificateMessage, ja3StringBuilder);
        appendIssuerLength(certificateMessage, ja3StringBuilder);
        appendSubjectLength(certificateMessage, ja3StringBuilder);
        appendPublicKeyOid(certificateMessage, ja3StringBuilder);
        appendSignatureAlgorithmOid(certificateMessage, ja3StringBuilder);
        return ja3StringBuilder.toString();
    }

    private static void appendCertificateCount(
            CertificateMessage certificateMessage, StringBuilder ja3StringBuilder) {
        ja3StringBuilder.append(certificateMessage.getCertificateEntryList().size());
        ja3StringBuilder.append(",");
    }

    private static void appendPublicKeyOid(
            CertificateMessage certificateMessage, StringBuilder ja3StringBuilder) {
        ja3StringBuilder.append(
                certificateMessage
                        .getX509CertificateListFromEntries()
                        .get(0)
                        .getPublicKey()
                        .getX509PublicKeyType()
                        .getOid()
                        .toString());
        ja3StringBuilder.append(",");
    }

    private static void appendSignatureAlgorithmOid(
            CertificateMessage certificateMessage, StringBuilder ja3StringBuilder) {
        ja3StringBuilder.append(
                certificateMessage
                        .getX509CertificateListFromEntries()
                        .get(0)
                        .getX509SignatureAlgorithm()
                        .getOid()
                        .toString());
    }

    private static void appendSubjectLength(
            CertificateMessage certificateMessage, StringBuilder ja3StringBuilder) {
        ja3StringBuilder.append(
                certificateMessage
                        .getX509CertificateListFromEntries()
                        .get(0)
                        .getSubjectCommonName()
                        .length());
    }

    private static void appendIssuerLength(
            CertificateMessage certificateMessage, StringBuilder ja3StringBuilder) {
        ja3StringBuilder.append(
                certificateMessage
                        .getX509CertificateListFromEntries()
                        .get(0)
                        .getIssuerCommonName()
                        .length());
    }

    private static void appendPointFormats(
            ClientHelloMessage clientHelloMessage, StringBuilder ja3StringBuilder) {
        ECPointFormatExtensionMessage ecPointFormatExtensionMessage =
                clientHelloMessage.getExtension(ECPointFormatExtensionMessage.class);
        if (ecPointFormatExtensionMessage != null) {
            byte[] formats = ecPointFormatExtensionMessage.getPointFormats().getValue();
            for (int i = 0; i < formats.length; i++) {
                ja3StringBuilder.append(ArrayConverter.byteToUnsignedInt(formats[i]));
                ja3StringBuilder.append("-");
            }
            if (ja3StringBuilder.length() > 0) {
                ja3StringBuilder.deleteCharAt(ja3StringBuilder.length() - 1);
            }
        }
    }

    private static void appendEllipticCurves(
            ClientHelloMessage clientHelloMessage, StringBuilder ja3StringBuilder) {
        EllipticCurvesExtensionMessage ellipticCurvesExtensionMessage =
                clientHelloMessage.getExtension(EllipticCurvesExtensionMessage.class);
        if (ellipticCurvesExtensionMessage != null) {
            boolean addedOne = false;
            ByteArrayInputStream curveStream =
                    new ByteArrayInputStream(
                            ellipticCurvesExtensionMessage.getSupportedGroups().getValue());
            while (curveStream.available() > 1) {
                try {
                    byte[] curve = curveStream.readNBytes(HandshakeByteLength.NAMED_GROUP);
                    NamedGroup group = NamedGroup.getNamedGroup(curve);
                    if (group != null && group.isGrease()) {
                        LOGGER.warn("NamedGroup is grease. Not considering it for JA3");
                        continue;
                    }
                    addedOne = true;
                    ja3StringBuilder.append(ArrayConverter.bytesToInt(curve));
                    ja3StringBuilder.append("-");

                } catch (IOException e) {
                    LOGGER.error("Could not read from input stream");
                }
            }
            if (curveStream.available() == 1) {
                LOGGER.warn(
                        "EllipticCurve length is not a multiple of 2. Not considering supperflous bytes for JA3");
            }
            if (ja3StringBuilder.length() > 0 && addedOne) {
                ja3StringBuilder.deleteCharAt(ja3StringBuilder.length() - 1);
            }
        }
        ja3StringBuilder.append(",");
    }

    private static void appendExtensions(
            HelloMessage helloMessage, StringBuilder ja3StringBuilder) {
        if (helloMessage.getExtensions() != null) {
            boolean addedOne = false;
            for (int i = 0; i < helloMessage.getExtensions().size(); i++) {
                ExtensionMessage extensionMessage = helloMessage.getExtensions().get(i);
                ExtensionType type =
                        ExtensionType.getExtensionType(
                                extensionMessage.getExtensionType().getValue());
                if (type != null && type.isGrease()) {
                    continue;
                }
                addedOne = true;
                ja3StringBuilder.append(
                        ArrayConverter.bytesToInt(extensionMessage.getExtensionType().getValue()));
                ja3StringBuilder.append("-");
            }
            if (ja3StringBuilder.length() > 0 && addedOne) {
                ja3StringBuilder.deleteCharAt(ja3StringBuilder.length() - 1);
            }
        }
        ja3StringBuilder.append(",");
    }

    private static void appendSelectedCipherSuite(
            ServerHelloMessage serverHelloMessage, StringBuilder ja3toStringBuilder) {
        ja3toStringBuilder.append(
                ArrayConverter.bytesToInt(serverHelloMessage.getSelectedCipherSuite().getValue()));
        ja3toStringBuilder.append(",");
    }

    private static void appendCipherSuites(
            ClientHelloMessage clientHelloMessage, StringBuilder ja3toStringBuilder) {
        ByteArrayInputStream cipherStream =
                new ByteArrayInputStream(clientHelloMessage.getCipherSuites().getValue());
        boolean addedOne = false;
        while (cipherStream.available() > 1) {
            try {
                byte[] cipherSuite = cipherStream.readNBytes(HandshakeByteLength.CIPHER_SUITE);
                ja3toStringBuilder.append(ArrayConverter.bytesToInt(cipherSuite));
                ja3toStringBuilder.append("-");
                addedOne = true;
            } catch (IOException e) {
                LOGGER.error("Could not read from input stream");
            }
        }
        if (ja3toStringBuilder.length() > 0 && addedOne) {
            ja3toStringBuilder.deleteCharAt(ja3toStringBuilder.length() - 1);
        }
        if (cipherStream.available() == 1) {
            LOGGER.warn(
                    "CipherSuite length is not a multiple of 2. Not considering supperflous bytes for JA3");
        }

        ja3toStringBuilder.append(",");
    }

    private static void appendVersion(HelloMessage helloMessage, StringBuilder ja3toStringBuilder) {
        ja3toStringBuilder
                .append(ArrayConverter.bytesToInt(helloMessage.getProtocolVersion().getValue()))
                .append(",");
    }
}
