/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.misc;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * If you run on an Oracle Java platform, it is possible that strong algorithms
 * are not allowed. In this case, you have to install a so called Unlimited
 * Strength Jurisdiction Policy.
 * 
 * We try to remove this limitation programmatically (see the field setters),
 * but it is possible that this does not work on all platforms.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class UnlimitedStrengthTest {

    final Logger logger = LogManager.getLogger(UnlimitedStrengthTest.class);

    @Test
    public void testAES256() throws Exception {
        try {
            Field isRestricted = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            isRestricted.setAccessible(true);
            if (Boolean.TRUE.equals(isRestricted.get(null))) {
                if (Modifier.isFinal(isRestricted.getModifiers())) {
                    Field modifiers = Field.class.getDeclaredField("modifiers");
                    modifiers.setAccessible(true);
                    modifiers.setInt(isRestricted, isRestricted.getModifiers() & ~Modifier.FINAL);
                }
                isRestricted.setBoolean(null, false); // isRestricted = false;
            }

            Cipher encryptCipher = Cipher.getInstance("AES/CBC/NoPadding", new BouncyCastleProvider());
            IvParameterSpec encryptIv = new IvParameterSpec(new byte[16]);
            SecretKey encryptKey = new SecretKeySpec(new byte[32], "AES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
        } catch (InvalidKeyException ex) {
            logger.warn("AES256 is probably not supported, you have to install Java Cryptography "
                    + "Extension (JCE) Unlimited Strength Jurisdiction Policy Files.");
        }
    }
}
