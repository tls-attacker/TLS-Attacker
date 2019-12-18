/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni;

import static org.junit.Assert.*;

import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class EsniWithCipherWrapperTest {

    @Test
    public void test() {

        byte[] sni = ArrayConverter
                .hexStringToByteArray("A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        byte[] key = ArrayConverter.hexStringToByteArray("82FC17E07BB336C770F423A78EB506A9");
        byte[] iv = ArrayConverter.hexStringToByteArray("EADB1A925CF4517998C312A7");
        int tagLength = 128;
        byte[] aad = ArrayConverter
                .hexStringToByteArray("0024001D00202A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C");
        byte[] expectedEncryptedSni = ArrayConverter
                .hexStringToByteArray("E3C48A706133928DB0E5307156F8FEA15A6D5451954D077B364FA40875517400AAC0A033D03971E8C7ACA8E8BBCC3BC8AAB9A74F645BA086127E9008592E0794491DBA30AE868721817646B8C503E134AA28834B755DE4847D1705ED9518B41B9D423B225CAE8B37BE6952CF0AE2B97D3860F6EC994A84C3273A26B8F8E39114539656B785D051C5475D072C5CA1EC054BB395AFEA5EA24A87692B0759B4928638F7D2BC6532C57DCAF3D53BEE825FDAED4D8E3BFB6C0153DF0D042D9A2BA7E8C16381234E71EC012749BF36D9E887A30191192A794B53F43948C2C7D1A59E54748007247E4EDFF3508DBC61AF01DFDF3A487D81315C615D3C1E1E819506B0FEEC8357E688D4841DE975B633CD18AB5031AEA93465A3382BA0A1E83FDE646DD99A349353");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(key);
        EncryptionCipher enc = CipherWrapper.getEncryptionCipher(CipherSuite.TLS_AES_128_GCM_SHA256,
                ConnectionEndType.CLIENT, keySet);

        byte[] resultEncryptedSni = null;
        try {
            resultEncryptedSni = enc.encrypt(iv, tagLength, aad, sni);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        assertArrayEquals(expectedEncryptedSni, resultEncryptedSni);
    }

}
