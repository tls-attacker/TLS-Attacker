/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import java.io.IOException;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.junit.jupiter.api.Test;

public class TLSGostKeyTransportBlobTest {

    @Test
    public void testGetInstance() {
        byte[] messageBytes =
                DataConverter.hexStringToByteArray(
                        "304330413028042083BE410A078B313050F47E89124DE9DCEC591B770D0AB638712E6F8412A874BA04046EE7685FA01506092A8503070102050101040850D55A4BB4D33355");
        TLSGostKeyTransportBlob blob = TLSGostKeyTransportBlob.getInstance(messageBytes);
        byte[] expected =
                DataConverter.hexStringToByteArray(
                        "83BE410A078B313050F47E89124DE9DCEC591B770D0AB638712E6F8412A874BA");
        byte[] actual = blob.getKeyBlob().getSessionEncryptedKey().getEncryptedKey();
        assertArrayEquals(expected, actual);

        expected = DataConverter.hexStringToByteArray("6EE7685F");
        actual = blob.getKeyBlob().getSessionEncryptedKey().getMacKey();
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testCreateInstance() throws IOException {
        byte[] key =
                DataConverter.hexStringToByteArray(
                        "83BE410A078B313050F47E89124DE9DCEC591B770D0AB638712E6F8412A874BA");
        byte[] mac = DataConverter.hexStringToByteArray("6EE7685F");
        byte[] ukm = DataConverter.hexStringToByteArray("50D55A4BB4D33355");

        Gost2814789EncryptedKey encryptedKey = new Gost2814789EncryptedKey(key, mac);
        GostR3410TransportParameters parameters =
                new GostR3410TransportParameters(
                        RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, null, ukm);
        GostR3410KeyTransport keyTransport = new GostR3410KeyTransport(encryptedKey, parameters);
        TLSGostKeyTransportBlob blob = new TLSGostKeyTransportBlob(keyTransport);

        byte[] expected =
                DataConverter.hexStringToByteArray(
                        "304330413028042083BE410A078B313050F47E89124DE9DCEC591B770D0AB638712E6F8412A874BA04046EE7685FA01506092A8503070102050101040850D55A4BB4D33355");
        assertArrayEquals(expected, blob.getEncoded());
    }
}
