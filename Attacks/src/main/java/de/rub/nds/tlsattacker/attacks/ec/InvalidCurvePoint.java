/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
public enum InvalidCurvePoint {

    SECP160K1(new BigInteger("6F6118AE7199611C0B4F95CFE3B7DEDA68301E69", 16), new BigInteger(
            "F6F9D0E04364C716C25263D7E44CA6C571D22597", 16), new BigInteger("5"), NamedGroup.SECP160K1, new BigInteger(
            "1EB1255E9C4C24DDEDDE4E0F7756123D7A823027", 16), new BigInteger("3D7F3F573E9BA07A843B3ADE7A12C88AD5DCC9FC",
            16), new BigInteger("7")),
    SECP160R1(new BigInteger("D465C0476AE02C499B0561B9C752C5CFEE8501ED", 16), new BigInteger(
            "5B6394C2C94D9214417E722792D0C07617CC31A6", 16), new BigInteger("5"), NamedGroup.SECP160R1, new BigInteger(
            "B65C8C2E4DAC05379029F9A01C110E7F470438EB", 16), new BigInteger("4DCECC50B0A5F478DEA08B9C95ED1B8D9CCA85D4",
            16), new BigInteger("7")),
    SECP160R2(new BigInteger("2790AABFE83C792584D45D5259ECCA28843D56AA", 16), new BigInteger(
            "5DE5B6B1EC7BDA3940ABA6AD9AE01008040D5949", 16), new BigInteger("5"), NamedGroup.SECP160R2, new BigInteger(
            "1263F47E04F675EF943F25EC205BBF1E96ABBCC7", 16), new BigInteger("C0363F5C199CC391A8CA102AA46736A99C59C4FE",
            16), new BigInteger("7")),
    SECP192K1(
            new BigInteger("7E89D82546F6EDC79CB91F2646E8D7E7AB3FC2F971F1713C", 16),
            new BigInteger("8A62DA9766C50A90A776C599C421632B46CA9878AB55AF19", 16),
            new BigInteger("7"),
            NamedGroup.SECP192K1,
            new BigInteger("AE33F2175E2DC0D0F1F553164E4DAAB998AF0BD83EE09438", 16),
            new BigInteger("B52C65D5C198450DB0B2FD239DE58E34BCD3F304936697A5", 16),
            new BigInteger("13")),
    SECP192R1(
            new BigInteger("F6DA5E72B35D837EDCDD6E8D211BDBB6565B9708D0447400", 16),
            new BigInteger("ED15E29256077E3D25C26753FEE705C02FFC0DC8EFDA443A", 16),
            new BigInteger("5"),
            NamedGroup.SECP192R1,
            new BigInteger("83121F7CA2E4E6B248A868F240B632AC6E9601936CBA0D5D", 16),
            new BigInteger("D15CA4A5728C75A72C152A3927474CE91A9216F548276EFD", 16),
            new BigInteger("7")),
    SECP224K1(
            new BigInteger("54510A6A85EF6144CA057E159DD83C240E3A69B06EE2CAC06BD25AC7", 16),
            new BigInteger("D2799F20E14C33AB704203F75EBDB38471919531970090DE8D12BC95", 16),
            new BigInteger("7"),
            NamedGroup.SECP224K1,
            new BigInteger("674858B9E39B1E4359DDD8AD714120C984888ED8073BF8B650AF7B96", 16),
            new BigInteger("1902C36C50FFE6BA2DEB89C7649B8A48B80AF4DDDCC849D8EBE91A9C", 16),
            new BigInteger("31")),
    SECP224R1(
            new BigInteger("A02F6D2FEBD6C53F11737C43EDDAF9A5026A21245DACA9342CFF7247", 16),
            new BigInteger("3B0781466C19DCCCAD13A2591A4DFAB7DADF210E9A150CE0C00137D9", 16),
            new BigInteger("5"),
            NamedGroup.SECP224R1,
            new BigInteger("E04C41F0E37355144656277C17E9439D779DBE28BA48F2E61A75EEFF", 16),
            new BigInteger("D5AAA43E42A0B640CF27C4AFF7C8508CD017207338B164F074BF0143", 16),
            new BigInteger("7")),
    SECP256K1(
            new BigInteger("5748979A06D28004D165F01FCA69C80DECAFB0119BA2A7C4C7F84C7AF2DCA311", 16),
            new BigInteger("D9625DF3DC92015DEB22AC7242ABEBE512B195E973BA657203F1BDEE8662B45A", 16),
            new BigInteger("7"),
            NamedGroup.SECP256K1,
            new BigInteger("1736E34CAA747C1B1EC4160765E9C0D50882138D13E13E5F2E34B24778433548", 16),
            new BigInteger("24A1D38F809C23EBC750A68D7EC3727AF19249E5A4F4ABAA14CD160C739B8C49", 16),
            new BigInteger("13")),
    SECP256R1(
            new BigInteger("21D2EFDDCFDF5C96268A16A8D5B8CB49EAD2DDE206259FE98686188A30CF0339", 16),
            new BigInteger("D440D09110D30D6CC3CDBBC38284109DB3ACA31F3C6717E29F1CE9D4088D4B1C", 16),
            new BigInteger("5"),
            NamedGroup.SECP256R1,
            new BigInteger("54A3B03165F9DF43B0D54251BE429D09AC599686639CC567D790736BC8DE7308", 16),
            new BigInteger("BBCC0B64E854B52E49D819BB03E4472ACBA7BFC9F090A8BF602F6ACD4719060D", 16),
            new BigInteger("7")),
    SECP384R1(
            new BigInteger(
                    "B68083A3FE4F9E46B78D7EDA7DD98FBB712EF7C9899F728D9633A3688B6DE446366668EA1E6CF80996B046719DAD63FF",
                    16), new BigInteger(
                    "FC00B0AFDC553D8A01336C78527231BF2D7C8BAD862225A07761BD0975E968E72204EBF877D9F67A22883512884BA870",
                    16), new BigInteger("5"), NamedGroup.SECP384R1, new BigInteger(
                    "78C45BF6A62393F086C74C9EE999911A1149F8328E9B8D385B2AED93DFD65D72962A745D4A2A24817E4EABB0666639B0",
                    16), new BigInteger(
                    "BF807F465329EF7753C64E4834C4EF68F1732776DB1FAEC725D0172F20A4988D90FE728FE16C0A54F621F378AFF3001D",
                    16), new BigInteger("7")),
    SECP521R1(
            new BigInteger(
                    "E04ED20B3289E72B4916D3C9095785488D309571BA7E39E0033DB72B471976133EE387F812A0DC2DE796A2C65ACCC220C2E11805FCADAF7F2D29826DF83C0B487F",
                    16),
            new BigInteger(
                    "7555B523F2A83D26CF76E8BF6F3BD55A6BD7307D617D10F7228ED84920C2832F5AB78472FB1E54E572703E70FB84F4F956F2AA2027F0156DDE1CCE729BA135B02C",
                    16),
            new BigInteger("5"),
            NamedGroup.SECP521R1,
            new BigInteger(
                    "9470BBD33D650A1CFE779BE2B55E2312C0972129267B843387B09426990FC9CFE06527DE124F07E65652F16E76D61079A166FE9B9F435B05FE89C56ECD425CB851",
                    16),
            new BigInteger(
                    "CEB883A8917D368E776877BCBAE2B2B57084631CA0FC406B3F147E9F2F2843D5C26C7885F2C38E47D3549C7E3E5D49DBC410D6484D7DA1792AFCB940825048DC6C",
                    16),
            new BigInteger("7")),
    BRAINPOOLP256R1(
            new BigInteger("475638180469F3128FCEACFF3D1B2A7052021FABE168456E724C82CE647A0B38", 16),
            new BigInteger("24392E4B249529608415683ABF8DF8017A577A447B791233BFF1F8D50003C3DA", 16),
            new BigInteger("5"),
            NamedGroup.BRAINPOOLP256R1,
            new BigInteger("7D26DAD103711071F75690F00EBD8C5D8CA2F0DD89FD7FB5938A9CA557B10022", 16),
            new BigInteger("21785CE72944C16797CD1014CBE23E5ED022206A679FCAA5832723C984124B4C", 16),
            new BigInteger("7")),
    BRAINPOOLP384R1(
            new BigInteger(
                    "7A15487AF637530E2BECC85585C2E36C21447AB4C786F08EF75A1EFBE7785016855AB3B6EFBB9F80517C23C1438A3F18",
                    16), new BigInteger(
                    "1C8AC00FBE2E3CD0994704AC81F8210A283F34D4F351F19525876A14719B8DDAC45315782BB7BBEAB47B0B6061788A9D",
                    16), new BigInteger("5"), NamedGroup.BRAINPOOLP384R1, new BigInteger(
                    "AA5BC981A7C36628E472AD4BA458CDC9BF895A0ED26399A17485A40B62376B0C1EA274F1296D308AD87BB77D76C83B6",
                    16), new BigInteger(
                    "60D9486AD043F67CA934338328C1C1EBA8600C587E9E435ABEA305D7B5954DE506B26708D6F1026F06A79CC7B3AD044F",
                    16), new BigInteger("7")),
    BRAINPOOLP512R1(
            new BigInteger(
                    "3A52E57C2D5BE39BB3F97C4CF90D81BEE7123CACBC6B7FF6EB03A164CCF0253FDF1AACF7C4AC6B820E6D48145D7854C67DEF4CADAB555D4609E279956450A610",
                    16),
            new BigInteger(
                    "1C41E102D5E9EF09CA132E808D87D1C0944951572E82C4F9FECACC80714C0C926E5DA09BD775F5C7E2BE54878EE2AC1A091A8653AE9961789202FD2BA21E7999",
                    16),
            new BigInteger("5"),
            NamedGroup.BRAINPOOLP512R1,
            new BigInteger(
                    "1ADF96CEF08D1587B145CEA629E7452240B5851C9DB46406FC75FA550BF38687D33AA0081490A8FAB73C59448CBF50A5623FA7C641A5D8A5FE372BA3CFE16133",
                    16),
            new BigInteger(
                    "2673C1B41A4A42697C771192DF770B787E1882F9AF6A965FAAF9A4262AD29D95BB9F6C87DF01AA29BC7646B901DF390317A97513728F5DA37E99A1C6A7575082",
                    16),
            new BigInteger("7"));

    private BigInteger publicPointBaseX;
    private BigInteger publicPointBaseY;
    private final NamedGroup namedGroup;
    private BigInteger order;

    private BigInteger redundantBaseX;
    private BigInteger redundantBaseY;
    private BigInteger redundantOrder;

    private InvalidCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order,
            NamedGroup namedGroup, BigInteger redundantBaseX, BigInteger redundantBaseY, BigInteger redundantOrder) {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.namedGroup = namedGroup;
        this.redundantBaseX = redundantBaseX;
        this.redundantBaseY = redundantBaseY;
        this.redundantOrder = redundantOrder;
    }

    public static InvalidCurvePoint fromNamedGroup(NamedGroup group) {
        for (InvalidCurvePoint point : values()) {
            if (point.getNamedGroup() == group) {
                return point;
            }
        }
        return null;
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    public BigInteger getOrder() {
        return order;
    }

    /**
     * @return the publicPointBaseX
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX
     *            the publicPointBaseX to set
     */
    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    /**
     * @return the publicPointBaseY
     */
    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    /**
     * @param publicPointBaseY
     *            the publicPointBaseY to set
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @param order
     *            the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }

    public BigInteger getRedundantBaseX() {
        return redundantBaseX;
    }

    public void setRedundantBaseX(BigInteger redundantBaseX) {
        this.redundantBaseX = redundantBaseX;
    }

    public BigInteger getRedundantBaseY() {
        return redundantBaseY;
    }

    public void setRedundantBaseY(BigInteger redundantBaseY) {
        this.redundantBaseY = redundantBaseY;
    }

    public BigInteger getRedundantOrder() {
        return redundantOrder;
    }

    public void setRedundantOrder(BigInteger redundantOrder) {
        this.redundantOrder = redundantOrder;
    }

}
