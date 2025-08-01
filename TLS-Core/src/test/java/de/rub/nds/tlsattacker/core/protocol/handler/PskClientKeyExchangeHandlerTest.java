/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import org.junit.jupiter.api.Test;

public class PskClientKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                PskClientKeyExchangeMessage, PskClientKeyExchangeHandler> {

    public PskClientKeyExchangeHandlerTest() {
        super(PskClientKeyExchangeMessage::new, PskClientKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class PskClientKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        PskClientKeyExchangeMessage message = new PskClientKeyExchangeMessage();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        message.getComputations()
                .setPremasterSecret(
                        DataConverter.hexStringToByteArray(
                                "0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"));
        message.getComputations()
                .setClientServerRandom(
                        DataConverter.hexStringToByteArray(
                                "a449532975d478abeefcfafa7522b9312bdbd0bb294fe460c4d52bab13a425b7594d0e9508874a67db6d9b8e91db4f38600e88f006bbe58f2b41deb6811c74cc"));

        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);

        handler.adjustContext(message);
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"),
                tlsContext.getPreMasterSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "FA1D499E795E936751AD43355C26857728E78ABE1C4BCAFA6EF3C90F6D9B9E49DF1ADE262F127EB2A23BB73E142EE122"),
                tlsContext.getMasterSecret());
    }
}
