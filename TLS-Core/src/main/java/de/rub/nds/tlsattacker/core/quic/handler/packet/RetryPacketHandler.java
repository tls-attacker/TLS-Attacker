/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.QuicFrameLayer;
import de.rub.nds.tlsattacker.core.layer.impl.QuicPacketLayer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetryPacketHandler extends LongHeaderPacketHandler<RetryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetryPacketHandler(QuicContext quicContext) {
        super(quicContext);
    }

    @Override
    public void adjustContext(RetryPacket packet) {
        if (!packet.verifyRetryIntegrityTag(quicContext)) {
            LOGGER.debug(
                    "Retry Integrity Tag is not verified, therefore we abort adjusting our context accordingly");
            return;
        }
        // update quic context
        quicContext.setInitialPacketToken(packet.getRetryToken().getValue());
        quicContext.setFirstDestinationConnectionId(packet.getSourceConnectionId().getValue());
        quicContext.setDestinationConnectionId(packet.getSourceConnectionId().getValue());

        LOGGER.info("Resetting QUIC frame and packet buffers");
        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) quicContext.getLayerStack().getLayer(QuicPacketLayer.class);
        QuicFrameLayer frameLayer =
                (QuicFrameLayer) quicContext.getLayerStack().getLayer(QuicFrameLayer.class);
        quicPacketLayer.clearReceivedPacketBuffer();
        frameLayer.clearCryptoFrameBuffer();

        // reset tls context to state prior the first client hello
        TlsContext tlsContext = quicContext.getContext().getTlsContext();
        tlsContext.setClientPskKeyExchangeModes(null);
        tlsContext.setClientRandom(null);
        tlsContext.setServerRandom(null);
        tlsContext.setDigest(new MessageDigestCollector());
        tlsContext.setHighestClientProtocolVersion(null);
        tlsContext.setClientSupportedCipherSuites((List<CipherSuite>) null);
        tlsContext.setClientSupportedCompressions((List<CompressionMethod>) null);
        tlsContext.setClientSupportedSignatureAndHashAlgorithms(
                (List<SignatureAndHashAlgorithm>) null);
        tlsContext.setClientSupportedCipherSuites((List<CipherSuite>) null);
        tlsContext.setClientNamedGroupsList((List<NamedGroup>) null);
        tlsContext.setClientSNIEntryList((List<SNIEntry>) null);
        tlsContext.setActiveClientKeySetType(Tls13KeySetType.NONE);
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.NONE);
        tlsContext.setClientSupportedProtocolVersions((List<ProtocolVersion>) null);
        tlsContext.setProposedAlpnProtocols(null);
        tlsContext.setSelectedSignatureAndHashAlgorithm(null);
        tlsContext.setLastClientHello(null);
        tlsContext.getProposedExtensions().clear();
        tlsContext.setInnerClientHello(null);
        tlsContext.init();

        // update quic keys
        try {
            QuicPacketCryptoComputations.calculateInitialSecrets(quicContext);
        } catch (CryptoException | NoSuchAlgorithmException e) {
            LOGGER.error("Could not initial secrets", e);
        }
    }
}
