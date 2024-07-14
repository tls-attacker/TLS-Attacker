/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;
import java.util.ArrayList;
import java.util.List;

// Largely a duplicate of VRFYReplyPreparator.
public class EXPNReplyPreparator extends SmtpReplyPreparator<SmtpEXPNReply> {
    public EXPNReplyPreparator(SmtpContext context, SmtpEXPNReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        getObject().setReplyLines(createReplyLines());
    }

    private List<String> createReplyLines() {
        List<String> replyLines = new ArrayList<>();

        if (isDescriptionOnlyResponse()) {
            replyLines.add(getObject().getDescription());
            return replyLines;
        }

        if (isDescriptionAndMailboxResponse()) {
            String mailbox = getObject().getMailboxes().get(0);
            if (getObject().mailboxesAreEnclosed()) mailbox = "<" + mailbox + ">";
            replyLines.add(getObject().getDescription() + " " + mailbox);
            return replyLines;
        }

        if (is250Response()) {
            boolean fullNamesExist = !getObject().getFullNames().isEmpty();
            boolean sizesDoNotMatch =
                    getObject().getMailboxes().size() != getObject().getFullNames().size();

            if (fullNamesExist && sizesDoNotMatch)
                throw new PreparationException(
                        "VRFY-Reply's fullNames and mailboxes sizes do not match.");

            if (getObject().getDescription() != null) replyLines.add(getObject().getDescription());

            for (int i = 0; i < getObject().getMailboxes().size(); i++) {
                replyLines.add(getFullNameAndMailboxString(i, fullNamesExist));
            }

            return replyLines;
        }

        throw new PreparationException(
                "Malformed VRFY-Reply: Reply cannot be matched with any valid replies.");
    }

    private String getFullNameAndMailboxString(int index, boolean containsFullNames) {
        StringBuilder sb = new StringBuilder();

        if (containsFullNames) {
            sb.append(getObject().getFullNames().get(index));
            sb.append(" ");
        }

        if (getObject().mailboxesAreEnclosed()) sb.append("<");
        sb.append(getObject().getMailboxes().get(index));
        if (getObject().mailboxesAreEnclosed()) sb.append(">");

        return sb.toString();
    }

    private boolean isDescriptionOnlyResponse() {
        return getObject().getDescription() != null
                && getObject().getFullNames().isEmpty()
                && getObject().getMailboxes().isEmpty();
    }

    private boolean isDescriptionAndMailboxResponse() {
        return getObject().getDescription() != null
                && getObject().getMailboxes().size() == 1
                && getObject().getFullNames().isEmpty();
    }

    private boolean is250Response() {
        return getObject().getDescription() != null
                        && getObject().getMailboxes().isEmpty()
                        && getObject().getFullNames().isEmpty()
                || getObject().getMailboxes().size() > 1;
    }
}
