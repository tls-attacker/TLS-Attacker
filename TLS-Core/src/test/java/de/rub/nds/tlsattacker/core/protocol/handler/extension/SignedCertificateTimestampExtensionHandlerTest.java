/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import org.junit.jupiter.api.Test;

public class SignedCertificateTimestampExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                SignedCertificateTimestampExtensionMessage,
                SignedCertificateTimestampExtensionHandler> {

    private final int lengthFirstPackage = 0;
    private final byte[] firstTimestamp = new byte[0];
    private final byte[] secondTimestamp =
            DataConverter.hexStringToByteArray(
                    "00ef007500ee4bbdb775ce60"
                            + "bae142691fabe19e66a30f7e5fb072d8"
                            + "8300c47b897aa8fdcb0000015b8fdb11"
                            + "14000004030046304402210089716b43"
                            + "ce66822358196424ebae1182ead83b7c"
                            + "126c664528ce222aa2b6e54d021f2377"
                            + "d1be9703495ed3ea3c3e60438381fa08"
                            + "e07713b168ff86091bfec8876d007600"
                            + "ddeb1d2b7a0d4fa6208b81ad8168707e"
                            + "2e8e9d01d55c888d3d11c4cdb6ecbecc"
                            + "0000015b8fdb0fa30000040300473045"
                            + "02210093ede0f0c9b7b1bed787c3a865"
                            + "e35829ab2c9d2cb748afe4181406a689"
                            + "897b4d0220593100bd6728a322a8d440"
                            + "40f2a950c7b99ed4f866ce847bc52606"
                            + "7ef710d303");
    private final int lengthSecondPackage = 241;

    public SignedCertificateTimestampExtensionHandlerTest() {
        super(
                SignedCertificateTimestampExtensionMessage::new,
                SignedCertificateTimestampExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        SignedCertificateTimestampExtensionMessage messageOne =
                new SignedCertificateTimestampExtensionMessage();
        messageOne.setSignedTimestamp(firstTimestamp);
        messageOne.setExtensionLength(lengthFirstPackage);

        handler.adjustContext(messageOne);
        assertArrayEquals(firstTimestamp, tlsContext.getSignedCertificateTimestamp());

        SignedCertificateTimestampExtensionMessage messageTwo =
                new SignedCertificateTimestampExtensionMessage();
        messageTwo.setSignedTimestamp(secondTimestamp);
        messageTwo.setExtensionLength(lengthSecondPackage);
        handler.adjustContext(messageTwo);

        assertArrayEquals(secondTimestamp, tlsContext.getSignedCertificateTimestamp());
    }
}
