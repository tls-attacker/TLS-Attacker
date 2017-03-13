/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import static de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public class ClientHelloHandler extends HandshakeMessageHandler<ClientHelloMessage> {

    public ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public Parser getParser(byte[] message, int pointer) {
        return new ClientHelloParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(ClientHelloMessage message) {
        return new ClientHelloPreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(ClientHelloMessage message) {
        return new ClientHelloSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ClientHelloMessage message) {
        setRandomContext(message.getUnixTime().getValue(), message.getRandom().getValue());
        tlsContext.setHighestClientProtocolVersion(ProtocolVersion.getProtocolVersion(message.getProtocolVersion()
                .getValue()));
        tlsContext.setClientSupportedCiphersuites(convertCipherSuites(message.getCipherSuites().getValue()));
        tlsContext.setClientSupportedCompressions(convertCompressionMethods(message.getCompressions().getValue()));
        if (message.getCookie() != null) {
            tlsContext.setDtlsHandshakeCookie(message.getCookie().getValue());
        }
        tlsContext.setSessionID(message.getSessionId().getValue());
        for (ExtensionMessage extension : message.getExtensions()) {
            throw new UnsupportedOperationException("Get extensionHandlers here and adjust context");
        }
    }

    private void setRandomContext(byte[] unixTime, byte[] random) {
        tlsContext.setClientRandom(ArrayConverter.concatenate(unixTime, random));
    }

    private List<CompressionMethod> convertCompressionMethods(byte[] bytesToConvert) {
        List<CompressionMethod> list = new LinkedList<>();
        for (byte b : bytesToConvert) {
            CompressionMethod method = CompressionMethod.getCompressionMethod(b);
            if (method == null) {
                LOGGER.warn("Could not convert " + b + " into a CompressionMethod");
            } else {
                list.add(method);
            }
        }
        return list;
    }

    private List<CipherSuite> convertCipherSuites(byte[] bytesToConvert) {
        if (bytesToConvert.length % 2 != 0) {
            LOGGER.warn("Cannot convert:" + ArrayConverter.bytesToHexString(bytesToConvert, false)
                    + " to a List<CipherSuite>");
            return null;
        }
        List<CipherSuite> list = new LinkedList<>();

        for (int i = 0; i < bytesToConvert.length; i = i + 2) {
            byte[] copied = new byte[2];
            copied[0] = bytesToConvert[i];
            copied[1] = bytesToConvert[i + 1];
            CipherSuite suite = CipherSuite.getCipherSuite(copied);
            if (suite == null) {
                LOGGER.warn("Cannot convert:" + ArrayConverter.bytesToHexString(copied) + " to a CipherSuite");
            } else {
                list.add(suite);
            }
        }
        return list;
    }
}
