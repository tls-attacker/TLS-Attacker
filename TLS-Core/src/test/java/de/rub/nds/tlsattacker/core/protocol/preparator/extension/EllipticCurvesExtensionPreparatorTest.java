/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class EllipticCurvesExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                EllipticCurvesExtensionMessage,
                EllipticCurvesExtensionSerializer,
                EllipticCurvesExtensionPreparator> {

    public EllipticCurvesExtensionPreparatorTest() {
        super(
                EllipticCurvesExtensionMessage::new,
                EllipticCurvesExtensionSerializer::new,
                EllipticCurvesExtensionPreparator::new);
    }

    /** Test of prepareExtensionContent method, of class EllipticCurvesExtensionPreparator. */
    @Test
    @Disabled("Not implemented")
    public void testPrepare() {}
}
