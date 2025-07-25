/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TokenbindingMessagePreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private Config config;

    private TokenBindingMessage message;

    private TokenBindingMessagePreparator preparator;

    @BeforeEach
    public void setUp() {
        config = new Config();
        TlsContext context =
                new Context(new State(config), new InboundConnection()).getTlsContext();
        Chooser chooser = context.getChooser();
        message = new TokenBindingMessage();
        preparator = new TokenBindingMessagePreparator(chooser, message);
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA256);
        context.setClientRandom(
                DataConverter.hexStringToByteArray(
                        "772EF595D8B1885E8F5DA5B0595B9E324E04571D5392BF99A046F00A1D331AEB"));
        context.setServerRandom(
                DataConverter.hexStringToByteArray(
                        "C3CE61F0F6A8335E98AF8725385586B41FEFF205B4E05A000823F78B5F8F5C02"));
        context.setMasterSecret(
                DataConverter.hexStringToByteArray(
                        "3B4B7628B03375E582E1398DA34FB51A9526847151337029CC15689130EE879B65DC461EF9DAEBB33C4C0FF5885FCE73"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
    }

    /** Test of prepareProtocolMessageContents method, of class TokenBindingMessagePreparator. */
    @Test
    public void testPrepareProtocolMessageContents() {
        preparator.prepare();
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(message);
        byte[] serialize = serializer.serialize();
        TokenBindingMessageParser selfParser =
                new TokenBindingMessageParser(new ByteArrayInputStream(serialize));
        TokenBindingMessage selfParsed = new TokenBindingMessage();
        selfParser.parse(selfParsed);
        assertNotNull(selfParsed);
        String base64 =
                "AIkAAgBBQM9eQES_uxoyRn0DDoYLcWqvm6Oo3p0lI1s3fRjdIj6dw8wLDf0RWkxuyNAmgAQkUWxm8_JfwS8MziBYVuJ5ECcAQHF_HGcPiSv_X60y5Ql-AxoqaWzwqXvpStEBgY_IX8kT_qAHsb5h38ZuQoWOaZVgqlF1sa70B4GVXxmi2JkdJYcAAA";
        byte[] decode = Base64.getUrlDecoder().decode(base64);
        TokenBindingMessageParser parser =
                new TokenBindingMessageParser(new ByteArrayInputStream(decode));
        message = new TokenBindingMessage();
        parser.parse(message);
        byte[] xBytes = new byte[32];
        System.arraycopy(message.getPoint().getValue(), 0, xBytes, 0, 32);
        LOGGER.debug("X: {}", xBytes);
        byte[] yBytes = new byte[32];
        System.arraycopy(message.getPoint().getValue(), 32, yBytes, 0, 32);
        LOGGER.debug("Y: {}", yBytes);
        BigInteger intX = new BigInteger(xBytes);
        LOGGER.debug("intx: {}", intX);

        ASN1Integer x = new ASN1Integer(xBytes);
        LOGGER.debug("xasn1: {}", x.getPositiveValue());

        byte[] rBytes = new byte[32];
        System.arraycopy(message.getSignature().getValue(), 0, rBytes, 0, 32);
        byte[] sBytes = new byte[32];
        System.arraycopy(message.getSignature().getValue(), 32, sBytes, 0, 32);
        LOGGER.debug("r: {}", rBytes);
        LOGGER.debug("s: {}", sBytes);
        LOGGER.debug("r: {}", new ASN1Integer(rBytes).getPositiveValue());
        LOGGER.debug("s: {}", new ASN1Integer(sBytes).getPositiveValue());
    }
}
