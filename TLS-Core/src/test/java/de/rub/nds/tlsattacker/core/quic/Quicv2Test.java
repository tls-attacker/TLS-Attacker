/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic;

import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Assert;
import org.junit.Test;

public class Quicv2Test {

    @Test
    public void versionDependentInitialSecretsTest()
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        // Check that we generate the correct version-dependent initial secrets
        QuicContext quicv1Context = calculateInitialSecretsForVersion(QuicVersion.VERSION_1);
        Assert.assertArrayEquals(
                quicv1Context.getInitialSalt(),
                ArrayConverter.hexStringToByteArray("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"));
        Assert.assertArrayEquals(
                quicv1Context.getInitialSecret(),
                ArrayConverter.hexStringToByteArray(
                        "e41d1a39cbb637025d7f57f60656d50b30d71f6271e9f3d5687ff4556cca69eb"));

        QuicContext quicv2Context = calculateInitialSecretsForVersion(QuicVersion.VERSION_2);
        Assert.assertArrayEquals(
                quicv2Context.getInitialSalt(),
                ArrayConverter.hexStringToByteArray("0dede3def700a6db819381be6e269dcbf9bd2ed9"));
        Assert.assertArrayEquals(
                quicv2Context.getInitialSecret(),
                ArrayConverter.hexStringToByteArray(
                        "dc59198d08f2dea69f55bb1d07622fd0ee9c0e5aca344977ee0d2099d5befddb"));

        // And check that we do not generate any secrets for "pseudo-versions"
        assertThrows(
                UnsupportedOperationException.class,
                () -> calculateInitialSecretsForVersion(QuicVersion.NEGOTIATION_VERSION));
        assertThrows(
                UnsupportedOperationException.class,
                () -> calculateInitialSecretsForVersion(QuicVersion.NULL_VERSION));
    }

    @Test
    public void versionDependent0RTTSecretsTest()
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        // Check that we generate the correct version-dependent initial secrets
        QuicContext quicv1Context = calculate0RTTSecretsForVersion(QuicVersion.VERSION_1);
        QuicContext quicv2Context = calculate0RTTSecretsForVersion(QuicVersion.VERSION_2);

        Assert.assertArrayEquals(
                quicv1Context.getZeroRTTClientSecret(), quicv2Context.getZeroRTTClientSecret());

        // And check that we do not generate any secrets for "pseudo-versions"
        assertThrows(
                UnsupportedOperationException.class,
                () -> calculateInitialSecretsForVersion(QuicVersion.NEGOTIATION_VERSION));
        assertThrows(
                UnsupportedOperationException.class,
                () -> calculateInitialSecretsForVersion(QuicVersion.NULL_VERSION));
    }

    private QuicContext calculateInitialSecretsForVersion(QuicVersion version)
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        Config config = new Config();
        config.setQuicVersion(version);
        QuicContext context =
                new Context(new State(config), new InboundConnection()).getQuicContext();
        // Fix connection ID for secret calculation
        context.setFirstDestinationConnectionId(new byte[8]);
        // We only calculate the initial secrets for this test because the other secrets require
        // more context and these should already be version-dependent
        QuicPacketCryptoComputations.calculateInitialSecrets(context);
        return context;
    }

    private QuicContext calculate0RTTSecretsForVersion(QuicVersion version)
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        Config config = new Config();
        config.setQuicVersion(version);
        Context context = new Context(new State(config), new InboundConnection());
        TlsContext tlsContext = context.getTlsContext();
        QuicContext quicContext = context.getQuicContext();
        tlsContext.setEarlyDataCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        tlsContext.setClientEarlyTrafficSecret(
                new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
        // Fix connection ID for secret calculation
        quicContext.setFirstDestinationConnectionId(new byte[8]);
        // We only calculate the initial secrets for this test because the other secrets require
        // more context and these should already be version-dependent
        QuicPacketCryptoComputations.calculate0RTTSecrets(quicContext);
        return quicContext;
    }
}
