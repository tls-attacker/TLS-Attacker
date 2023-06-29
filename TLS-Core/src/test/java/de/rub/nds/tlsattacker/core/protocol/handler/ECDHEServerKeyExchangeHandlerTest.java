/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ECDHEServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                ECDHEServerKeyExchangeMessage<?>,
                ServerKeyExchangeHandler<ECDHEServerKeyExchangeMessage<?>>> {

    public ECDHEServerKeyExchangeHandlerTest() {
        super(ECDHEServerKeyExchangeMessage::new, ECDHEServerKeyExchangeHandler::new);
    }

    /** Test of adjustContext method, of class ECDHEServerKeyExchangeHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        message.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
        message.setNamedGroup(NamedGroup.SECP256R1.getValue());
        message.setPublicKey(
                ArrayConverter.hexStringToByteArray(
                        "04f660a88e9dae015684be56c25610f9c62cf120cb075eea60c560e5e6dd5d10ef6e391d7213a298985470dc2268949317ce24940d474a0c8386ab13b312ffc104"));
        message.setPublicKeyLength(65);
        message.prepareComputations();
        message.getComputations().setPremasterSecret(new byte[] {0, 1, 2, 3});
        message.getComputations().setPrivateKey(new BigInteger("12345"));
        handler.adjustContext(message);
        assertNull(context.getPreMasterSecret());
        // assertNull(context.getMasterSecret());//TODO assert master secret was
        // computed correctly
    }

    @Test
    public void testadjustContextWithoutComputations() {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        message.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
        message.setNamedGroup(NamedGroup.SECP256R1.getValue());
        message.setPublicKey(
                ArrayConverter.hexStringToByteArray(
                        "04f660a88e9dae015684be56c25610f9c62cf120cb075eea60c560e5e6dd5d10ef6e391d7213a298985470dc2268949317ce24940d474a0c8386ab13b312ffc104"));
        message.setPublicKeyLength(65);
        handler.adjustContext(message);
        assertNull(context.getPreMasterSecret());
        assertNull(context.getMasterSecret());
    }
}
