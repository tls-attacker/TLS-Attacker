/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRequestPreparator
        extends HandshakeMessagePreparator<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] certTypes;
    private byte[] sigHashAlgos;
    private final CertificateRequestMessage msg;

    public CertificateRequestPreparator(Chooser chooser, CertificateRequestMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateRequestMessage");
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            prepareCertificateRequestContext(msg);
            prepareCertificateRequestContextLength(msg);
            prepareExtensions();
            prepareExtensionLength();
        } else {
            certTypes =
                    convertClientCertificateTypes(chooser.getConfig().getClientCertificateTypes());
            prepareClientCertificateTypes(certTypes, msg);
            prepareClientCertificateTypesCount(msg);
            prepareDistinguishedNames(msg);
            prepareDistinguishedNamesLength(msg);
            sigHashAlgos =
                    convertSigAndHashAlgos(chooser.getServerSupportedSignatureAndHashAlgorithms());
            prepareSignatureHashAlgorithms(msg);
            prepareSignatureHashAlgorithmsLength(msg);
        }
    }

    private byte[] convertClientCertificateTypes(List<ClientCertificateType> typeList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ClientCertificateType type : typeList) {
            try {
                stream.write(type.getArrayValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare CertificateRequestMessage. Failed to write ClientCertificateType into message",
                        ex);
            }
        }
        return stream.toByteArray();
    }

    private byte[] convertSigAndHashAlgos(List<SignatureAndHashAlgorithm> algoList) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (SignatureAndHashAlgorithm algo : algoList) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare CertificateRequestMessage. Failed to write SignatureAndHash Algorithm into "
                                + "message",
                        ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareClientCertificateTypes(byte[] certTypes, CertificateRequestMessage msg) {
        msg.setClientCertificateTypes(certTypes);
        LOGGER.debug("ClientCertificateTypes: {}", msg.getClientCertificateTypes().getValue());
    }

    private void prepareClientCertificateTypesCount(CertificateRequestMessage msg) {
        msg.setClientCertificateTypesCount(msg.getClientCertificateTypes().getValue().length);
        LOGGER.debug(
                "ClientCertificateTypesCount: " + msg.getClientCertificateTypesCount().getValue());
    }

    private void prepareDistinguishedNames(CertificateRequestMessage msg) {
        msg.setDistinguishedNames(chooser.getConfig().getDistinguishedNames());
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNames().getValue());
    }

    private void prepareDistinguishedNamesLength(CertificateRequestMessage msg) {
        msg.setDistinguishedNamesLength(msg.getDistinguishedNames().getValue().length);
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNamesLength().getValue());
    }

    private void prepareSignatureHashAlgorithms(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithms(sigHashAlgos);
        LOGGER.debug("SignatureHashAlgorithms: {}", msg.getSignatureHashAlgorithms().getValue());
    }

    private void prepareSignatureHashAlgorithmsLength(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithmsLength(msg.getSignatureHashAlgorithms().getValue().length);
        LOGGER.debug(
                "SignatureHashAlgorithmsLength: "
                        + msg.getSignatureHashAlgorithmsLength().getValue());
    }

    private void prepareCertificateRequestContext(CertificateRequestMessage msg) {
        msg.setCertificateRequestContext(chooser.getConfig().getDefaultCertificateRequestContext());
        LOGGER.debug(
                "CertificateRequestContext: {}", msg.getCertificateRequestContext().getValue());
    }

    private void prepareCertificateRequestContextLength(CertificateRequestMessage msg) {
        msg.setCertificateRequestContextLength(
                msg.getCertificateRequestContext().getValue().length);
        LOGGER.debug(
                "CertificateRequestContextLength: "
                        + msg.getCertificateRequestContextLength().getValue());
    }
}
