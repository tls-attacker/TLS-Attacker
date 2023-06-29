/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class RemBufferedChExtensionsActionTest
        extends AbstractActionTest<RemBufferedChExtensionsAction> {

    private final ClientHelloMessage ch;
    private final List<ExtensionType> remove;
    private final List<ExtensionType> expected;
    private List<ExtensionType> actual;
    private byte[] expectedBytes;
    private int expectedLength;
    private int expectedMsgLength;

    public RemBufferedChExtensionsActionTest() {
        super(new RemBufferedChExtensionsAction(), RemBufferedChExtensionsAction.class);

        expected = new ArrayList<>();
        expected.add(ExtensionType.EC_POINT_FORMATS);
        expected.add(ExtensionType.ELLIPTIC_CURVES);
        expected.add(ExtensionType.EXTENDED_MASTER_SECRET);
        expected.add(ExtensionType.ENCRYPT_THEN_MAC);
        expectedBytes =
                ArrayConverter.hexStringToByteArray(
                        "000B00020100000A000A000800130017001800190017000000160000");
        expectedLength = 28;

        Config config = state.getConfig();
        TlsContext context = state.getTlsContext();
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddEncryptThenMacExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        config.setAddSignatureAlgorithmsCertExtension(false);
        config.setDefaultClientNamedGroups(
                NamedGroup.SECP192R1,
                NamedGroup.SECP256R1,
                NamedGroup.SECP384R1,
                NamedGroup.SECP521R1);
        config.setDefaultServerNamedGroups(
                NamedGroup.SECP192R1,
                NamedGroup.SECP256R1,
                NamedGroup.SECP384R1,
                NamedGroup.SECP521R1);

        ch = new ClientHelloMessage(config);
        ClientHelloPreparator preparator = new ClientHelloPreparator(context.getChooser(), ch);
        preparator.prepare();
        expectedMsgLength = ch.getLength().getValue();
        context.getMessageBuffer().add(ch);
        remove = new ArrayList<>();
    }

    private List<ExtensionType> typesFromMessageList(List<ExtensionMessage> extMsgs) {
        List<ExtensionType> types = new ArrayList<>();
        for (ExtensionMessage msg : extMsgs) {
            types.add(msg.getExtensionTypeConstant());
        }
        return types;
    }

    private void compareList() {
        actual = typesFromMessageList(ch.getExtensions());
        assertEquals(expected, actual, "extension list should be adjusted");
    }

    private void compareFields() {
        byte[] actualBytes = ch.getExtensionBytes().getValue();
        int actualLength = ch.getExtensionsLength().getValue();
        int actualMsgLength = ch.getLength().getValue();
        assertArrayEquals(expectedBytes, actualBytes, "bytes should be adjusted");
        assertEquals(expectedLength, actualLength, "bytes lengths should be adjusted");
        assertEquals(expectedMsgLength, actualMsgLength, "message lengths should be adjusted");
        assertTrue(action.isExecuted());
    }

    private void setExpectedFields(String extensionBytes) {
        expectedBytes = ArrayConverter.hexStringToByteArray(extensionBytes);
        int diff = expectedLength;
        expectedLength = extensionBytes.length() / 2;
        diff -= expectedLength;
        expectedMsgLength -= diff;
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        actual = typesFromMessageList(ch.getExtensions());
        compareList();
        compareFields();
    }

    @Test
    public void testRemoveSingleExtensionIsOk() throws Exception {
        expected.remove(ExtensionType.ELLIPTIC_CURVES);
        setExpectedFields("000B000201000017000000160000");
        action.setRemoveExtensions(ExtensionType.ELLIPTIC_CURVES);
        super.testExecute();
        compareList();
        compareFields();
    }

    @Test
    public void testRemoveMultipleExtensionsIsOk() throws Exception {
        remove.add(ExtensionType.ENCRYPT_THEN_MAC);
        remove.add(ExtensionType.ELLIPTIC_CURVES);
        expected.removeAll(remove);
        setExpectedFields("000B0002010000170000");
        action.setRemoveExtensions(remove);
        super.testExecute();
        compareList();
        compareFields();
    }

    @Test
    public void testRemoveNonProposedExtensionsIsOk() throws Exception {
        remove.add(ExtensionType.ALPN);
        remove.add(ExtensionType.RENEGOTIATION_INFO);
        remove.add(ExtensionType.ELLIPTIC_CURVES);
        expected.removeAll(remove);
        setExpectedFields("000B000201000017000000160000");
        action.setRemoveExtensions(remove);
        super.testExecute();
        compareList();
        compareFields();
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    @Override
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        action.setRemoveExtensions(ExtensionType.TOKEN_BINDING, ExtensionType.ALPN);
        super.testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject();
    }
}
