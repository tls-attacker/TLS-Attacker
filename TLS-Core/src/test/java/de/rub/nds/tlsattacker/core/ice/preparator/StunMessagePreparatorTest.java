/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.preparator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class StunMessagePreparatorTest {
    @Test
    public void testEncodeClassTypeWithMethodType() {

        State state = new State(new Config());
        for (StunMethodType methodType : StunMethodType.values()) {
            for (StunMessageClass messageClass : StunMessageClass.values()) {
                StunMessage message = new StunMessage(messageClass, methodType);
                StunMessagePreparator preparator =
                        new StunMessagePreparator(state.getTlsContext().getChooser(), message);
                preparator.prepare();
                StunMethodType tempMethodType =
                        StunMethodType.getStunMethodTypeFromRawBytes(
                                message.getStunMessageTypeBytes().getValue());
                StunMessageClass classType =
                        StunMessageClass.getMessageClass(
                                message.getStunMessageTypeBytes().getValue());
                assertEquals(messageClass, classType);
                assertEquals(methodType, tempMethodType);
            }
        }
    }
}
