/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.StatePlaintext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.util.TimeHelper;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessagePreparator extends HandshakeMessagePreparator<NewSessionTicketMessage> {

    private final NewSessionTicketMessage msg;

    public NewSessionTicketMessagePreparator(Chooser chooser, NewSessionTicketMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    private long generateTicketLifetimeHint() {
        long ticketLifeTimeHint = chooser.getSessionTicketLifetimeHint();
        return ticketLifeTimeHint;
    }

    private void prepareTicketLifetimeHint(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(generateTicketLifetimeHint());
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint());
    }

    private void prepareTicket(NewSessionTicketMessage msg) {
        msg.prepareTicket();
        SessionTicket newticket = msg.getTicket();
        newticket.setKeyName(chooser.getSessionTicketKeyName());

        byte[] keyaes = chooser.getSessionTicketKeyAES();

        byte[] iv = new byte[16];
        RandomHelper.getRandom().nextBytes(iv);
        newticket.setIV(iv);

        StatePlaintext plainstate = generateStatePlaintext();
        byte[] plainstateSerialized = plainstate.serialize();
        byte[] encryptedstate = StaticTicketCrypto.encryptAES_128_CBC(plainstateSerialized, keyaes, iv);
        newticket.setEncryptedState(encryptedstate);

        byte[] keyhmac = chooser.getSessionTicketKeyHMAC();
        // Mac(Name + IV + TicketLength + Ticket)
        byte[] macinput = ArrayConverter.concatenate(chooser.getSessionTicketKeyName(), iv);
        macinput = ArrayConverter.concatenate(macinput, ArrayConverter.intToBytes(encryptedstate.length, HandshakeByteLength.ENCRYPTED_STATE_LENGTH));
        macinput = ArrayConverter.concatenate(macinput, encryptedstate);
        byte[] hmac = StaticTicketCrypto.generateHMAC_SHA256(macinput, keyhmac);
        newticket.setMAC(hmac);

        msg.setTicketLength(chooser.getSessionTicketKeyName().length + iv.length + encryptedstate.length + hmac.length);
        LOGGER.debug("Ticket: " + msg.getTicket().toString());
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing NewSessionTicketMessage");
        prepareTicketLifetimeHint(msg);
        prepareTicket(msg);
    }

    /**
     * Generates the StatePlaintext for the SessionTicket, mayby put this as
     * static function in the StatePlaintext class for better testing/debugging
     * 
     * @return A struct with Stateinformation defined in
     *         https://tools.ietf.org/html/rfc5077#section-4
     */
    private StatePlaintext generateStatePlaintext() {
        StatePlaintext plainstate = new StatePlaintext();
        plainstate.setCipherSuite(chooser.getSelectedCipherSuite().getValue());
        plainstate.setCompressionMethod(chooser.getSelectedCompressionMethod().getValue());
        plainstate.setMasterSecret(chooser.getMasterSecret());
        plainstate.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());

        long timestamp = TimeHelper.getTime() / 1000;
        plainstate.setTimestamp(timestamp);

        if (chooser.isClientAuthentication()) {
            // TODO: How to diffentiate between PSK and Certauth and where to
            // get the data
        } else {
            plainstate.setClientAuthenticationType(ClientAuthenticationType.ANONYMOUS.getValue());
            plainstate.setClientAuthenticationData(new byte[0]);
            plainstate.setClientAuthenticationDataLength(0);
        }

        return plainstate;
    }

}