/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class XorMappedAddressAttributePreparator
        extends StunAttributePreparator<XorMappedAddressAttribute> {

    private Logger LOGGER = LogManager.getLogger();

    public XorMappedAddressAttributePreparator(
            Chooser chooser, XorMappedAddressAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setReservedByte(new byte[1]);
        getObject()
                .setProtocolFamily(
                        chooser.getConfig().getIceConfig().getProtocolFamily().getValue());
        getObject().setIpAddress(chooser.getConfig().getIceConfig().getDefaultAddress());

        getObject().setPort(chooser.getConfig().getIceConfig().getDefaultPort());
        getObject()
                .setXorMappedIpAddress(
                        mapXor(
                                getObject().getIpAddress().getValue(),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
        getObject()
                .setXorMappedPort(
                        mapXor(
                                ArrayConverter.intToBytes(
                                        getObject().getPort().getValue(),
                                        IceByteLengths.STUN_XOR_MAPPED_ATTRIBUTE_PORT),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
    }

    public byte[] mapXor(byte[] value, byte[] transactionId) {
        byte[] mappedAddress = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            if (transactionId.length > i) {
                mappedAddress[i] = (byte) (value[i] ^ transactionId[i]);
            } else {
                LOGGER.warn(
                        "Transaction ID too short to map value. Using plain value in remaining positions.");
                mappedAddress[i] = value[i];
            }
        }
        return mappedAddress;
    }

    @Override
    public void prepareAfterParse() {
        getObject()
                .setIpAddress(
                        mapXor(
                                getObject().getXorMappedIpAddress().getValue(),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
        getObject()
                .setPort(
                        ArrayConverter.bytesToInt(
                                mapXor(
                                        getObject().getXorMappedPort().getValue(),
                                        chooser.getConfig()
                                                .getIceConfig()
                                                .getDefaultStunTransactionId())));
    }
}
