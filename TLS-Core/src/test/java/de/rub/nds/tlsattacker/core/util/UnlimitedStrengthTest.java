/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * If you run on an Oracle Java platform, it is possible that strong algorithms
 * are not allowed. In this case, you have to install a so called Unlimited
 * Strength Jurisdiction Policy. We try to remove this limitation
 * programmatically (see the field setters), but it is possible that this does
 * not work on all platforms.
 */
public class UnlimitedStrengthTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    public void testAES256() throws Exception {
        try {
            new GeneralDelegate().applyDelegate(Config.createConfig());

            Cipher encryptCipher = Cipher.getInstance("AES/CBC/NoPadding");
            IvParameterSpec encryptIv = new IvParameterSpec(new byte[16]);
            SecretKey encryptKey = new SecretKeySpec(new byte[32], "AES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
        } catch (InvalidKeyException ex) {
            LOGGER.warn("AES256 is probably not supported, you have to install Java Cryptography "
                    + "Extension (JCE) Unlimited Strength Jurisdiction Policy Files.");
            LOGGER.debug(ex);
            fail();
        }
    }
}
