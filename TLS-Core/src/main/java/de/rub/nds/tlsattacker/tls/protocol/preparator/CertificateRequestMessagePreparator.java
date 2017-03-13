/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessagePreparator extends HandshakeMessagePreparator<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    private final CertificateRequestMessage message;

    public CertificateRequestMessagePreparator(TlsContext context, CertificateRequestMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        byte[] certTypes = convertClientCertificateTypes(context.getConfig().getClientCertificateTypes());
        message.setClientCertificateTypes(certTypes);
        message.setClientCertificateTypesCount(message.getClientCertificateTypes().getValue().length);
        message.setDistinguishedNames(context.getConfig().getDistinguishedNames());
        message.setDistinguishedNamesLength(message.getDistinguishedNames().getValue().length);
        byte[] sigHashAlgos = convertSigAndHashAlgos(context.getConfig().getSupportedSignatureAndHashAlgorithms());
        message.setSignatureHashAlgorithms(sigHashAlgos);
        message.setSignatureHashAlgorithmsLength(message.getSignatureHashAlgorithms().getValue().length);
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
                        "Could not prepare CertificateRequestMessage. Failed to write SignatureAndHash Algorithm into message",
                        ex);
            }
        }
        return stream.toByteArray();
    }

}
