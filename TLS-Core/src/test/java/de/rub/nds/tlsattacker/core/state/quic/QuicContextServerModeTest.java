/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state.quic;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

/** Tests that QuicContext correctly defers Initial secret derivation in server mode */
public class QuicContextServerModeTest {

    @Test
    public void testServerModeDefersDcidAndSecrets() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        new ServerDelegate() {
            {
                setPort(4433);
            }
        }.applyDelegate(config);

        State state = new State(config);
        QuicContext quicContext = state.getContext().getQuicContext();

        assertNull(
                quicContext.getFirstDestinationConnectionId(),
                "Server mode must not generate firstDestinationConnectionId at init");
        assertEquals(
                0,
                quicContext.getDestinationConnectionId().length,
                "Server mode destinationConnectionId should be empty until client's Initial arrives");
        assertFalse(
                quicContext.isInitialSecretsInitialized(),
                "Server mode must not derive Initial secrets at init");
        assertNotNull(
                quicContext.getSourceConnectionId(),
                "Server mode should still generate its own SCID");
        assertTrue(
                quicContext.getSourceConnectionId().length > 0, "Server SCID should be non-empty");
    }

    @Test
    public void testClientModeInitializesSecretsImmediately() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);

        State state = new State(config);
        QuicContext quicContext = state.getContext().getQuicContext();

        assertNotNull(
                quicContext.getFirstDestinationConnectionId(),
                "Client mode must generate firstDestinationConnectionId at init");
        assertTrue(
                quicContext.getFirstDestinationConnectionId().length > 0,
                "Client DCID should be non-empty");
        assertArrayEquals(
                quicContext.getFirstDestinationConnectionId(),
                quicContext.getDestinationConnectionId(),
                "Client mode: destinationConnectionId must equal firstDestinationConnectionId");
        assertTrue(
                quicContext.isInitialSecretsInitialized(),
                "Client mode must derive Initial secrets at init");
        assertNotNull(quicContext.getInitialClientKey(), "Client Initial key should be derived");
        assertNotNull(quicContext.getInitialServerKey(), "Server Initial key should be derived");
    }

    /** Verifies that both client and server modes derive the same keys from the same DCID. */
    @Test
    public void testSameDcidProducesSameSecrets() throws Exception {
        byte[] sharedDcid = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        // Client mode: set a known DCID
        Config clientConfig = new Config();
        new QuicDelegate(true).applyDelegate(clientConfig);
        State clientState = new State(clientConfig);
        QuicContext clientCtx = clientState.getContext().getQuicContext();
        clientCtx.setFirstDestinationConnectionId(sharedDcid);
        clientCtx.setInitialSecretsInitialized(false);
        QuicPacketCryptoComputations.calculateInitialSecrets(clientCtx);

        // Server mode: simulate receiving a client Initial with the same DCID
        Config serverConfig = new Config();
        new QuicDelegate(true).applyDelegate(serverConfig);
        new ServerDelegate() {
            {
                setPort(4433);
            }
        }.applyDelegate(serverConfig);
        State serverState = new State(serverConfig);
        QuicContext serverCtx = serverState.getContext().getQuicContext();

        assertFalse(serverCtx.isInitialSecretsInitialized(), "Pre-condition: no secrets yet");
        serverCtx.setFirstDestinationConnectionId(sharedDcid);
        QuicPacketCryptoComputations.calculateInitialSecrets(serverCtx);

        assertTrue(serverCtx.isInitialSecretsInitialized(), "Secrets should now be initialized");
        assertArrayEquals(
                clientCtx.getInitialClientKey(),
                serverCtx.getInitialClientKey(),
                "Client Initial key must match between client-mode and server-mode derivation");
        assertArrayEquals(
                clientCtx.getInitialServerKey(),
                serverCtx.getInitialServerKey(),
                "Server Initial key must match between client-mode and server-mode derivation");
        assertArrayEquals(
                clientCtx.getInitialClientIv(),
                serverCtx.getInitialClientIv(),
                "Client Initial IV must match");
        assertArrayEquals(
                clientCtx.getInitialServerIv(),
                serverCtx.getInitialServerIv(),
                "Server Initial IV must match");
    }

    @Test
    public void testResetReturnsToUninitializedInServerMode() {
        Config config = new Config();
        new QuicDelegate(true).applyDelegate(config);
        new ServerDelegate() {
            {
                setPort(4433);
            }
        }.applyDelegate(config);

        State state = new State(config);
        QuicContext quicContext = state.getContext().getQuicContext();

        // Simulate having received a client Initial and derived secrets
        byte[] clientDcid = new byte[] {0x0a, 0x0b, 0x0c, 0x0d};
        quicContext.setFirstDestinationConnectionId(clientDcid);
        quicContext.setDestinationConnectionId(clientDcid);
        try {
            de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations
                    .calculateInitialSecrets(quicContext);
        } catch (Exception e) {
            fail("Secret derivation should succeed: " + e.getMessage());
        }
        assertTrue(quicContext.isInitialSecretsInitialized());

        // Reset should return to deferred state
        quicContext.reset();

        assertNull(
                quicContext.getFirstDestinationConnectionId(),
                "After reset, server-mode firstDCID should be null again");
        assertEquals(
                0,
                quicContext.getDestinationConnectionId().length,
                "After reset, server-mode DCID should be empty again");
        assertFalse(
                quicContext.isInitialSecretsInitialized(),
                "After reset, server-mode secrets should not be initialized");
    }
}
