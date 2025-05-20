/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRequestHandler extends HandshakeMessageHandler<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(CertificateRequestMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().is13()) {
            adjustCertificateRequestContext(message);
            adjustServerSupportedSignatureAndHashAlgorithms(message);
        } else {
            adjustClientCertificateTypes(message);
            adjustDistinguishedNames(message);
            if (tlsContext.getChooser().getSelectedProtocolVersion() == ProtocolVersion.TLS12
                    || tlsContext.getChooser().getSelectedProtocolVersion()
                            == ProtocolVersion.DTLS12) {
                adjustServerSupportedSignatureAndHashAlgorithms(message);
            }
        }
    }

    private void adjustServerSupportedSignatureAndHashAlgorithms(
            CertificateRequestMessage message) {
        List<SignatureAndHashAlgorithm> algoList;
        if (tlsContext.getChooser().getSelectedProtocolVersion().is13()) {
            SignatureAndHashAlgorithmsExtensionMessage extension =
                    message.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
            if (extension != null) {
                algoList =
                        convertSignatureAndHashAlgorithms(
                                extension.getSignatureAndHashAlgorithms().getValue());
            } else {
                if (message.getSignatureHashAlgorithms() != null) {
                    algoList =
                            convertSignatureAndHashAlgorithms(
                                    message.getSignatureHashAlgorithms().getValue());
                } else {
                    algoList = new LinkedList<>();
                }
            }
        } else {
            if (message.getSignatureHashAlgorithms() != null) {
                algoList =
                        convertSignatureAndHashAlgorithms(
                                message.getSignatureHashAlgorithms().getValue());
            } else {
                algoList = new LinkedList<>();
            }
        }
        tlsContext.setServerSupportedSignatureAndHashAlgorithms(algoList);
        LOGGER.debug("Set ServerSupportedSignatureAndHashAlgorithms to {}", algoList);
    }

    private void adjustDistinguishedNames(CertificateRequestMessage message) {
        if (message.getDistinguishedNames() != null
                && message.getDistinguishedNames().getValue() != null) {
            byte[] distinguishedNames = message.getDistinguishedNames().getValue();
            tlsContext.setDistinguishedNames(distinguishedNames);
            LOGGER.debug("Set DistinguishedNames in Context to {}", distinguishedNames);
        } else {
            LOGGER.debug("Not adjusting DistinguishedNames");
        }
    }

    private void adjustClientCertificateTypes(CertificateRequestMessage message) {
        List<ClientCertificateType> clientCertTypes =
                convertClientCertificateTypes(message.getClientCertificateTypes().getValue());
        tlsContext.setClientCertificateTypes(clientCertTypes);
        LOGGER.debug("Set ClientCertificateType in Context to {} ", clientCertTypes);
    }

    private List<ClientCertificateType> convertClientCertificateTypes(byte[] bytesToConvert) {
        List<ClientCertificateType> list = new LinkedList<>();
        for (byte b : bytesToConvert) {
            ClientCertificateType type = ClientCertificateType.getClientCertificateType(b);
            if (type == null) {
                LOGGER.warn("Cannot convert: {} to a ClientCertificateType", b);
            } else {
                list.add(type);
            }
        }
        return list;
    }

    private List<SignatureAndHashAlgorithm> convertSignatureAndHashAlgorithms(
            byte[] bytesToConvert) {
        if (bytesToConvert.length % 2 != 0) {
            LOGGER.warn("Cannot convert: {} to a List<SignatureAndHashAlgorithm>", bytesToConvert);
            return new LinkedList<>();
        }
        List<SignatureAndHashAlgorithm> list = new LinkedList<>();

        for (int i = 0; i < bytesToConvert.length; i += 2) {
            byte[] copied = new byte[2];
            copied[0] = bytesToConvert[i];
            copied[1] = bytesToConvert[i + 1];
            SignatureAndHashAlgorithm algo =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(copied);
            if (algo != null) {
                list.add(algo);
            } else {
                LOGGER.warn("Cannot convert: {} to a SignatureAndHashAlgorithm", copied);
            }
        }
        return list;
    }

    private void adjustCertificateRequestContext(CertificateRequestMessage msg) {
        ModifiableByteArray context = msg.getCertificateRequestContext();
        if (context == null) {
            LOGGER.warn("CertificateRequestContext is NULL");
            throw new IllegalArgumentException(
                    "CertificateRequestContext is NULL");
        }
        tlsContext.setCertificateRequestContext(context.getValue());

    }
}
