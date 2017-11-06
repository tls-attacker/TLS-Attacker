/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateRequestMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class CertificateRequestHandler extends HandshakeMessageHandler<CertificateRequestMessage> {

    public CertificateRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateRequestMessageParser getParser(byte[] message, int pointer) {
        return new CertificateRequestMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public CertificateRequestMessagePreparator getPreparator(CertificateRequestMessage message) {
        return new CertificateRequestMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public CertificateRequestMessageSerializer getSerializer(CertificateRequestMessage message) {
        return new CertificateRequestMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(CertificateRequestMessage message) {
        adjustClientCertificateTypes(message);
        adjustDistinguishedNames(message);
        adjustServerSupportedSignatureAndHashAlgorithms(message);
    }

    private void adjustServerSupportedSignatureAndHashAlgorithms(CertificateRequestMessage message) {
        List<SignatureAndHashAlgorithm> algoList = convertSignatureAndHashAlgorithms(message
                .getSignatureHashAlgorithms().getValue());
        tlsContext.setServerSupportedSignatureAndHashAlgorithms(algoList);
        LOGGER.debug("Set ServerSupportedSignatureAndHashAlgortihms to " + algoList.toString());
    }

    private void adjustDistinguishedNames(CertificateRequestMessage message) {
        if (message.getDistinguishedNames() != null && message.getDistinguishedNames().getValue() != null) {
            byte[] distinguishedNames = message.getDistinguishedNames().getValue();
            tlsContext.setDistinguishedNames(distinguishedNames);
            LOGGER.debug("Set DistinguishedNames in Context to "
                    + ArrayConverter.bytesToHexString(distinguishedNames, false));
        } else {
            LOGGER.debug("Not adjusting DistinguishedNames");
        }
    }

    private void adjustClientCertificateTypes(CertificateRequestMessage message) {
        List<ClientCertificateType> clientCertTypes = convertClientCertificateTypes(message.getClientCertificateTypes()
                .getValue());
        tlsContext.setClientCertificateTypes(clientCertTypes);
        LOGGER.debug("Set ClientCertificateType in Context to " + clientCertTypes.toString());
    }

    private List<ClientCertificateType> convertClientCertificateTypes(byte[] bytesToConvert) {
        List<ClientCertificateType> list = new LinkedList<>();
        for (byte b : bytesToConvert) {
            ClientCertificateType type = ClientCertificateType.getClientCertificateType(b);
            if (type == null) {
                LOGGER.warn("Cannot convert:" + b + " to a ClientCertificateType");
            } else {
                list.add(type);
            }
        }
        return list;
    }

    private List<SignatureAndHashAlgorithm> convertSignatureAndHashAlgorithms(byte[] bytesToConvert) {
        if (bytesToConvert.length % 2 != 0) {
            LOGGER.warn("Cannot convert:" + ArrayConverter.bytesToHexString(bytesToConvert, false)
                    + " to a List<SignatureAndHashAlgorithm>");
            return new LinkedList<>();
        }
        List<SignatureAndHashAlgorithm> list = new LinkedList<>();

        for (int i = 0; i < bytesToConvert.length; i += 2) {
            byte[] copied = new byte[2];
            copied[0] = bytesToConvert[i];
            copied[1] = bytesToConvert[i + 1];
            SignatureAndHashAlgorithm algo = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(copied);
            list.add(algo);
        }
        return list;
    }
}
