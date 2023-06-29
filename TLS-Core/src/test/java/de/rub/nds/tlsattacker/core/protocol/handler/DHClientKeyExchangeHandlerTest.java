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
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class DHClientKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                DHClientKeyExchangeMessage<?>,
                ClientKeyExchangeHandler<DHClientKeyExchangeMessage<?>>> {

    public DHClientKeyExchangeHandlerTest() {
        super(DHClientKeyExchangeMessage::new, DHClientKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class DHClientKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        DHClientKeyExchangeMessage message = new DHClientKeyExchangeMessage();
        message.setPublicKey(new byte[] {1});
        message.prepareComputations();
        message.getComputations()
                .setPremasterSecret(
                        ArrayConverter.hexStringToByteArray(
                                "17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf"));
        message.getComputations()
                .setClientServerRandom(
                        ArrayConverter.hexStringToByteArray(
                                "c8c9c788adbd9dc72b5dd0635f9e2576e09c87b67e045c026ffa3281069601fd594c07e445947b545a746fcbc094e12427e0286be2199300925a81be02bf5467"));
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        handler.adjustContext(message);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "17631f03fb5f59e65ef9b581bb6494e7304e2eaffb07ff7356cf62db1c44f4e4c15614909a3f2980c1908da2200924a23bc037963c204048cc77b1bcab5e6c9ef2c32928bcbdc0b664535885d46a9d4af4104eba4d7428c5741cf1c74bbd54d8e7ea16eaa126218286639a740fc39173e8989aea7f4b4440e1cad321315911fc4a8135d1217ebada1c70cb4ce99ff11dc8c8ca4ffc3c48a9f3f2143588a8fec147a6c3da4d36df18cf075eb7de187d83c7e3b7fd27124741a4b8809bed4f43ed9a434ce59c6a33277be96d8ef27b8e6a59d70bf6a04a86f04dfc37ab69ad90da53dfc1ea27f60a32ee7608b2197943bf8673dbe68003277bfd40b40d18b1a3bf"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "4a0a7f6a0598acb36684359e1a19d848ab03b3ba1167430471166d94dcf8315d1c4290c9d9e40c50ae834df7b4f4bdef"),
                context.getMasterSecret());
        assertEquals(context.getClientDhPublicKey(), BigInteger.ONE);
    }
}
