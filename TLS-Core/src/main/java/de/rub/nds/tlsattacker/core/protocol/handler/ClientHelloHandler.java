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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;

public class ClientHelloHandler extends HandshakeMessageHandler<ClientHelloMessage> {

    public ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ClientHelloParser getParser(byte[] message, int pointer) {
        return new ClientHelloParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ClientHelloPreparator getPreparator(ClientHelloMessage message) {
        return new ClientHelloPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ClientHelloSerializer getSerializer(ClientHelloMessage message) {
        return new ClientHelloSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ClientHelloMessage message) {
        adjustProtocolVersion(message);
        adjustSessionID(message);
        adjustClientSupportedCipherSuites(message);
        adjustClientSupportedCompressions(message);
        if (isCookieFieldSet(message)) {
            adjustDTLSCookie(message);
        }
        if (message.getExtensions() != null) {
            KeyShareExtensionHandler keyShareHandler = null;
            KeyShareExtensionMessage keyShareExtension = null;
            for (ExtensionMessage extension : message.getExtensions()) {
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                        extension.getExtensionTypeConstant(), HandshakeMessageType.CLIENT_HELLO);
                if (handler instanceof KeyShareExtensionHandler) {
                    keyShareHandler = (KeyShareExtensionHandler) handler;
                    keyShareExtension = (KeyShareExtensionMessage) extension;
                } else {
                    handler.adjustTLSContext(extension);
                }
            }
            if (keyShareHandler != null) // delay KeyShare to process PSK first
            {
                keyShareHandler.adjustTLSContext(keyShareExtension);
            }
        }
        adjustRandomContext(message);
    }

    private boolean isCookieFieldSet(ClientHelloMessage message) {
        return message.getCookie() != null;
    }

    private void adjustClientSupportedCipherSuites(ClientHelloMessage message) {
        List<CipherSuite> suiteList = convertCipherSuites(message.getCipherSuites().getValue());
        tlsContext.setClientSupportedCiphersuites(suiteList);
        if (suiteList != null) {
            LOGGER.debug("Set ClientSupportedCiphersuites in Context to " + suiteList.toString());
        } else {
            LOGGER.debug("Set ClientSupportedCiphersuites in Context to " + null);
        }
    }

    private void adjustClientSupportedCompressions(ClientHelloMessage message) {
        List<CompressionMethod> compressionList = convertCompressionMethods(message.getCompressions().getValue());
        tlsContext.setClientSupportedCompressions(compressionList);
        LOGGER.debug("Set ClientSupportedCompressions in Context to " + compressionList.toString());
    }

    private void adjustDTLSCookie(ClientHelloMessage message) {
        byte[] dtlsCookie = message.getCookie().getValue();
        tlsContext.setDtlsCookie(dtlsCookie);
        LOGGER.debug("Set DTLS Cookie in Context to " + ArrayConverter.bytesToHexString(dtlsCookie));
    }

    private void adjustSessionID(ClientHelloMessage message) {
        byte[] sessionId = message.getSessionId().getValue();
        tlsContext.setClientSessionId(sessionId);
        LOGGER.debug("Set SessionId in Context to " + ArrayConverter.bytesToHexString(sessionId, false));
    }

    private void adjustProtocolVersion(ClientHelloMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        if (version != null) {
            tlsContext.setHighestClientProtocolVersion(version);
            LOGGER.debug("Set HighestClientProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                    + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustRandomContext(ClientHelloMessage message) {
        tlsContext.setClientRandom(message.getRandom().getValue());
        LOGGER.debug("Set ClientRandom in Context to " + ArrayConverter.bytesToHexString(tlsContext.getClientRandom()));
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

        for (int i = 0; i < bytesToConvert.length; i += 2) {
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

    @Override
    public void adjustTlsContextAfterSerialize(ClientHelloMessage message) {
        if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT
                && tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            tlsContext.setActiveKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
            LOGGER.debug("Set activeKeySetType in Context to " + tlsContext.getActiveKeySetType());
        }
    }

}
