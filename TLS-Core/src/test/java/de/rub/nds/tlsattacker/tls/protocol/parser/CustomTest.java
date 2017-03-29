/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CustomTest {

    public CustomTest() {
    }

    @Test
    public void testParse() {
        DHEServerKeyExchangeParser parser = new DHEServerKeyExchangeParser(
                0,
                ArrayConverter
                        .hexStringToByteArray("0080FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0001020080DAC902E6E622F59C07E4CB4355D7B7743429BF0D061B9D78381490E27CF7DCCDC3F5CE121C103BFD18F44E57CA762645C4EFBE74D431206FDA46DFD25B4071DA3EC02AB6A8173C6C0A584E67179836BDEDEA02286D17CA69AB959F3B27FB4EE3F1CC626AD05A833603CC191F307ED378AA9C824F6CE42CFBE56A0ACC0498A467008093A00EDD17482244CC0081C9109EAFFAB53636A9F2FC09F39CEE87334A9592BE455DC1A49E144DE488182640FA801046FC7D76CB0F206DB51211285BA8233EFA2DF93AAA812CFDFE87F84153EA8066E520968786828C48C16AF78CE046EFC0A8F48B486D06D09C69BFCE788C7296DF6A0991466573F85A0A015D7B59DDF9E502"),
                ProtocolVersion.TLS10);
        DHEServerKeyExchangeMessage msg = new DHEServerKeyExchangeMessage();
        parser.parseHandshakeMessageContent(msg);
        System.out.println(msg.toString());
    }
}
