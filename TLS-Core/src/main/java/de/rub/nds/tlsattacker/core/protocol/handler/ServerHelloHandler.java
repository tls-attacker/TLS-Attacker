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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.Session;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;

public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerHelloMessagePreparator getPreparator(ServerHelloMessage message) {
        return new ServerHelloMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ServerHelloMessageSerializer getSerializer(ServerHelloMessage message) {
        return new ServerHelloMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public ServerHelloParser getParser(byte[] message, int pointer) {
        return new ServerHelloParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public void adjustTLSContext(ServerHelloMessage message) {
        adjustSelectedProtocolVersion(message);
        if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            adjustSelectedCompression(message);
            adjustSelectedSessionID(message);
        }
        adjustSelectedCiphersuite(message);
        adjustServerRandom(message);
        adjustExtensions(message, HandshakeMessageType.SERVER_HELLO);
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()) {
                setServerRecordCipher();
            }
        }
        adjustPRF(message);
        if (tlsContext.hasSession(tlsContext.getChooser().getServerSessionId())) {
            LOGGER.info("Resuming Session");
            LOGGER.debug("Loading Mastersecret");
            Session session = tlsContext.getSession(tlsContext.getChooser().getServerSessionId());
            tlsContext.setMasterSecret(session.getMasterSecret());
            setRecordCipher();
        }
    }

    private void adjustSelectedCiphersuite(ServerHelloMessage message) {
        CipherSuite suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        if (suite != null) {
            tlsContext.setSelectedCipherSuite(suite);
            LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
        } else {
            LOGGER.warn("Unknown CipherSuite, did not adjust Context");
        }
    }

    private void adjustServerRandom(ServerHelloMessage message) {
        tlsContext.setServerRandom(message.getRandom().getValue());
        LOGGER.debug("Set ServerRandom in Context to " + ArrayConverter.bytesToHexString(tlsContext.getServerRandom()));
    }

    private void adjustSelectedCompression(ServerHelloMessage message) {
        CompressionMethod method = CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod()
                .getValue());
        if (method != null) {
            tlsContext.setSelectedCompressionMethod(method);
            LOGGER.debug("Set SelectedCompressionMethod in Context to " + method.name());
        } else {
            LOGGER.warn("Unknown CompressionAlgorithm, did not adjust Context");
        }
    }

    private void adjustSelectedSessionID(ServerHelloMessage message) {
        byte[] sessionID = message.getSessionId().getValue();
        tlsContext.setServerSessionId(sessionID);
        LOGGER.debug("Set SessionID in Context to " + ArrayConverter.bytesToHexString(sessionID, false));

    }

    private void adjustSelectedProtocolVersion(ServerHelloMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        if (version != null) {
            tlsContext.setSelectedProtocolVersion(version);
            LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                    + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustPRF(ServerHelloMessage message) {
        Chooser chooser = tlsContext.getChooser();
        if (!chooser.getSelectedProtocolVersion().isSSL()) {
            tlsContext.setPrfAlgorithm(AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                    chooser.getSelectedCipherSuite()));
        }
    }

    private void setRecordCipher() {
        KeySet keySet = getKeySet(tlsContext, Tls13KeySetType.NONE);
        LOGGER.debug("Setting new Cipher in RecordLayer");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
    }

    private void setServerRecordCipher() {
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        LOGGER.debug("Setting cipher for server to use handshake secrets");
        KeySet serverKeySet = getKeySet(tlsContext, tlsContext.getActiveServerKeySetType());
        RecordCipher recordCipherServer = RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, tlsContext
                .getChooser().getSelectedCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipherServer);

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecryptionCipher();
        } else {
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.getRecordLayer().updateEncryptionCipher();
        }
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(context, tlsContext.getChooser().getSelectedProtocolVersion(),
                    keySetType);
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ServerHelloMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            setServerRecordCipher();
        }
    }
}
