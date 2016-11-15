/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionHandler;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class MaxFragmentLengthExtensionHandlerTest {

    private final byte[] extensionMessage = {(byte) 00, (byte) 01, // Extension type
        (byte) 00, (byte) 02, // Extension length
        (byte) 00, (byte) 04}; // max_fragment_length is set to 2^12
    
    @Test
    public void testParseExtension () {
        MaxFragmentLengthExtensionHandler handler = MaxFragmentLengthExtensionHandler.getInstance();
        int newPointer = handler.parseExtension(extensionMessage, 0);
        Assert.assertEquals((int) 6, newPointer);
        
    }
}
