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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.PWDClientKeyExchangePreparator;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class PWDClientKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                PWDClientKeyExchangeMessage, PWDClientKeyExchangeHandler> {

    public PWDClientKeyExchangeHandlerTest() {
        super(PWDClientKeyExchangeMessage::new, PWDClientKeyExchangeHandler::new);
    }

    @Test
    @Override
    public void testadjustContext() {
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.BRAINPOOLP256R1);
        context.setSelectedGroup(NamedGroup.BRAINPOOLP256R1);
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        context.setClientPWDUsername("fred");
        context.getConfig().setDefaultPWDPassword("barney");
        context.setServerPWDElement(
                PointFormatter.formatFromByteArray(
                        NamedGroup.BRAINPOOLP256R1,
                        ArrayConverter.hexStringToByteArray(
                                "0422bbd56b481d7fa90c35e8d42fcd06618a0778de506b1bc38882abc73132eef37f02e13bd544acc145bdd806450d43be34b9288348d03d6cd9832487b129dbe1")));
        context.setServerPWDScalar(
                new BigInteger(
                        "2f704896699fc424d3cec33717644f5adf7f68483424ee51492bb96613fc4921", 16));

        PWDClientKeyExchangeMessage message = new PWDClientKeyExchangeMessage();
        PWDClientKeyExchangePreparator prep =
                new PWDClientKeyExchangePreparator(context.getChooser(), message);
        prep.prepare();
        handler.adjustContext(message);

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "782FB8A017109CF92CA56D67BCBE4C19196E6EFC7CD396A91512BB66ED65E9BA"),
                context.getPreMasterSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "BF1B217B1B01D1E16519BD686871B0D3C4609DC5EC9EA4766B674A75CFCA819412DD9AF47CD5B303BBD9DBA8996ED73A"),
                context.getMasterSecret());
    }
}
