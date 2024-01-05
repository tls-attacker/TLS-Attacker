/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class KeyShareExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                KeyShareExtensionMessage, KeyShareExtensionHandler> {

    public KeyShareExtensionHandlerTest() {
        super(
                KeyShareExtensionMessage::new,
                (TlsContext context) -> new KeyShareExtensionHandler(context));
    }

    /** Test of adjustContext method, of class KeyShareExtensionHandler. Group: ECDH_X25519 */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        List<KeyShareEntry> pairList = new LinkedList<>();
        KeyShareEntry pair =
                new KeyShareEntry(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                ArrayConverter.hexStringToByteArray(
                                        "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF")));
        pair.setPublicKey(
                ArrayConverter.hexStringToByteArray(
                        "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"));
        pair.setGroup(NamedGroup.ECDH_X25519.getValue());
        pairList.add(pair);
        msg.setKeyShareList(pairList);
        handler.adjustContext(msg);
        assertNotNull(context.getServerKeyShareStoreEntry());
        KeyShareStoreEntry entry = context.getServerKeyShareStoreEntry();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c"),
                entry.getPublicKey());
        assertSame(NamedGroup.ECDH_X25519, entry.getGroup());
    }
}
