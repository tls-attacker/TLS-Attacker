/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RequestItemV2Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

public class CertificateStatusRequestV2ExtensionSerializerTest {

    private final byte[] expectedBytes = ArrayConverter
            .hexStringToByteArray("00110013001101000E0007000501020304050003010203");
    private final int reqListLength = 0x11;
    private final int extensionLength = 0x13;
    private final ExtensionType type = ExtensionType.STATUS_REQUEST_V2;
    private final RequestItemV2 item = new RequestItemV2(1, 14, 7, 3, new byte[] { 0x01, 0x02, 0x03 });
    private final List<ResponderId> responderIdList = Arrays.asList(new ResponderId(5, new byte[] { 0x01, 0x02, 0x03,
            0x04, 0x05 }));
    private final byte[] respoderIdListBytes = new byte[] { 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };

    @Test
    public void testSerializer() {
        item.setResponderIdList(responderIdList);
        item.setResponderIdListBytes(respoderIdListBytes);
        RequestItemV2Preparator preparator = new RequestItemV2Preparator(new TlsContext().getChooser(), item);
        preparator.prepare();

        for (ResponderId id : responderIdList) {
            ResponderIdPreparator responderPreparator = new ResponderIdPreparator(new TlsContext().getChooser(), id);
            responderPreparator.prepare();
        }

        CertificateStatusRequestV2ExtensionMessage msg = new CertificateStatusRequestV2ExtensionMessage();
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setStatusRequestListLength(reqListLength);
        msg.setStatusRequestList(Arrays.asList(item));

        CertificateStatusRequestV2ExtensionSerializer serializer = new CertificateStatusRequestV2ExtensionSerializer(
                msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
