/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** s_client -keymatexport “label” -keymatexportlen 20 */
public class TokenCalculatorTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new Context(new State(new Config()), new InboundConnection()).getTlsContext();
    }

    /**
     * Test of calculateEKM method, of class TokenCalculator.
     *
     * @throws de.rub.nds.protocol.exception.CryptoException
     */
    @Test
    public void testCalculateEKM() throws CryptoException {
        context.setMasterSecret(
                DataConverter.hexStringToByteArray(
                        "6D7B3B37807AFB5BAFEB46A3BA1AD1BCE0CF31DA68D635EC9A8130CB9A0241C437DF4D988ED2D00D3AC5FECEB056C3C7"));
        context.setClientRandom(
                DataConverter.hexStringToByteArray(
                        "bb34871e6271841dc8fddb4e2ec5fdf92fec4b144434096b98d5a091511f89f0"));
        context.setServerRandom(
                DataConverter.hexStringToByteArray(
                        "15c9f5b1c30fb1e0b87cebf5756200555dba15241c890652d3306e8194858735"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        assertArrayEquals(
                DataConverter.hexStringToByteArray("C2199B4A1CD5404F03DBAAB9B69ECBA607687555"),
                TokenCalculator.calculateEKM(context.getChooser(), 20));
    }

    /**
     * Test of calculateEKM method, of class TokenCalculator.
     *
     * @throws de.rub.nds.protocol.exception.CryptoException
     */
    @Test
    public void testCalculateSSLEKM() throws CryptoException {
        context.setMasterSecret(
                DataConverter.hexStringToByteArray(
                        "6D7B3B37807AFB5BAFEB46A3BA1AD1BCE0CF31DA68D635EC9A8130CB9A0241C437DF4D988ED2D00D3AC5FECEB056C3C7"));
        context.setClientRandom(
                DataConverter.hexStringToByteArray(
                        "bb34871e6271841dc8fddb4e2ec5fdf92fec4b144434096b98d5a091511f89f0"));
        context.setServerRandom(
                DataConverter.hexStringToByteArray(
                        "15c9f5b1c30fb1e0b87cebf5756200555dba15241c890652d3306e8194858735"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        assertArrayEquals(
                DataConverter.hexStringToByteArray("C2199B4A1CD5404F03DBAAB9B69ECBA607687555"),
                TokenCalculator.calculateEKM(context.getChooser(), 20));
    }
}
