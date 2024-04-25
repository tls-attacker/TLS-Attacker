/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;
import de.rub.nds.tlsattacker.core.stun.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class XorPeerAddressAttributePreparator
        extends StunAttributePreparator<XorPeerAddressAttribute> {

    private Logger LOGGER = LogManager.getLogger();

    public XorPeerAddressAttributePreparator(
            Chooser chooser, XorPeerAddressAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setReservedByte(new byte[0]);
        getObject()
                .setProtocolFamily(
                        chooser.getConfig().getIceConfig().getProtocolFamily().getValue());
        getObject().setIpAddress(chooser.getConfig().getIceConfig().getDefaultAddress());

        getObject().setPort(chooser.getConfig().getIceConfig().getDefaultPort());
        getObject()
                .setXorPeerIpAddress(
                        mapXor(
                                getObject().getIpAddress().getValue(),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
        getObject()
                .setXorPeerPort(
                        mapXor(
                                ArrayConverter.intToBytes(
                                        getObject().getPort().getValue(),
                                        IceByteLengths.STUN_XOR_PEER_ATTRIBUTE_PORT),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
    }

    public byte[] mapXor(byte[] value, byte[] transactionId) {
        byte[] peerAddress = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            if (transactionId.length > i) {
                peerAddress[i] = (byte) (value[i] ^ transactionId[i]);
            } else {
                LOGGER.warn(
                        "Transaction ID too short to map value. Using plain value in remaining positions.");
                peerAddress[i] = value[i];
            }
        }
        return peerAddress;
    }

    @Override
    public void prepareAfterParse() {
        getObject()
                .setIpAddress(
                        mapXor(
                                getObject().getXorPeerIpAddress().getValue(),
                                chooser.getConfig().getIceConfig().getDefaultStunTransactionId()));
        getObject()
                .setPort(
                        ArrayConverter.bytesToInt(
                                mapXor(
                                        getObject().getXorPeerPort().getValue(),
                                        chooser.getConfig()
                                                .getIceConfig()
                                                .getDefaultStunTransactionId())));
    }
}
