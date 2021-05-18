/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 */

package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
@SuppressWarnings("SpellCheckingInspection")
public class InvalidCurvePoint {

    private BigInteger publicPointBaseX;
    private BigInteger publicPointBaseY;
    private final NamedGroup namedGroup;
    private BigInteger order;

    private InvalidCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order,
        NamedGroup namedGroup) {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.namedGroup = namedGroup;
    }

    /**
     * Provides an Invalid Curve point of small order (usually 5 or 7)
     * 
     * @param  group
     * @return       InvalidCurvePoint
     */
    public static InvalidCurvePoint smallOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new InvalidCurvePoint(new BigInteger("6F6118AE7199611C0B4F95CFE3B7DEDA68301E69", 16),
                    new BigInteger("F6F9D0E04364C716C25263D7E44CA6C571D22597", 16), new BigInteger("5"),
                    NamedGroup.SECP160K1);
            case SECP160R1:
                return new InvalidCurvePoint(new BigInteger("D465C0476AE02C499B0561B9C752C5CFEE8501ED", 16),
                    new BigInteger("5B6394C2C94D9214417E722792D0C07617CC31A6", 16), new BigInteger("5"),
                    NamedGroup.SECP160R1);
            case SECP160R2:
                return new InvalidCurvePoint(new BigInteger("2790AABFE83C792584D45D5259ECCA28843D56AA", 16),
                    new BigInteger("5DE5B6B1EC7BDA3940ABA6AD9AE01008040D5949", 16), new BigInteger("5"),
                    NamedGroup.SECP160R2);
            case SECP192K1:
                return new InvalidCurvePoint(new BigInteger("7E89D82546F6EDC79CB91F2646E8D7E7AB3FC2F971F1713C", 16),
                    new BigInteger("8A62DA9766C50A90A776C599C421632B46CA9878AB55AF19", 16), new BigInteger("7"),
                    NamedGroup.SECP192K1);
            case SECP192R1:
                return new InvalidCurvePoint(new BigInteger("F6DA5E72B35D837EDCDD6E8D211BDBB6565B9708D0447400", 16),
                    new BigInteger("ED15E29256077E3D25C26753FEE705C02FFC0DC8EFDA443A", 16), new BigInteger("5"),
                    NamedGroup.SECP192R1);
            case SECP224K1:
                return new InvalidCurvePoint(
                    new BigInteger("54510A6A85EF6144CA057E159DD83C240E3A69B06EE2CAC06BD25AC7", 16),
                    new BigInteger("D2799F20E14C33AB704203F75EBDB38471919531970090DE8D12BC95", 16), new BigInteger("7"),
                    NamedGroup.SECP224K1);
            case SECP224R1:
                return new InvalidCurvePoint(
                    new BigInteger("A02F6D2FEBD6C53F11737C43EDDAF9A5026A21245DACA9342CFF7247", 16),
                    new BigInteger("3B0781466C19DCCCAD13A2591A4DFAB7DADF210E9A150CE0C00137D9", 16), new BigInteger("5"),
                    NamedGroup.SECP224R1);
            case SECP256K1:
                return new InvalidCurvePoint(
                    new BigInteger("5748979A06D28004D165F01FCA69C80DECAFB0119BA2A7C4C7F84C7AF2DCA311", 16),
                    new BigInteger("D9625DF3DC92015DEB22AC7242ABEBE512B195E973BA657203F1BDEE8662B45A", 16),
                    new BigInteger("7"), NamedGroup.SECP256K1);
            case SECP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("21D2EFDDCFDF5C96268A16A8D5B8CB49EAD2DDE206259FE98686188A30CF0339", 16),
                    new BigInteger("D440D09110D30D6CC3CDBBC38284109DB3ACA31F3C6717E29F1CE9D4088D4B1C", 16),
                    new BigInteger("5"), NamedGroup.SECP256R1);
            case SECP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "B68083A3FE4F9E46B78D7EDA7DD98FBB712EF7C9899F728D9633A3688B6DE446366668EA1E6CF80996B046719DAD63FF",
                    16),
                    new BigInteger(
                        "FC00B0AFDC553D8A01336C78527231BF2D7C8BAD862225A07761BD0975E968E72204EBF877D9F67A22883512884BA870",
                        16),
                    new BigInteger("5"), NamedGroup.SECP384R1);
            case SECP521R1:
                return new InvalidCurvePoint(new BigInteger(
                    "E04ED20B3289E72B4916D3C9095785488D309571BA7E39E0033DB72B471976133EE387F812A0DC2DE796A2C65ACCC220C2E11805FCADAF7F2D29826DF83C0B487F",
                    16),
                    new BigInteger(
                        "7555B523F2A83D26CF76E8BF6F3BD55A6BD7307D617D10F7228ED84920C2832F5AB78472FB1E54E572703E70FB84F4F956F2AA2027F0156DDE1CCE729BA135B02C",
                        16),
                    new BigInteger("5"), NamedGroup.SECP521R1);
            case BRAINPOOLP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("475638180469F3128FCEACFF3D1B2A7052021FABE168456E724C82CE647A0B38", 16),
                    new BigInteger("24392E4B249529608415683ABF8DF8017A577A447B791233BFF1F8D50003C3DA", 16),
                    new BigInteger("5"), NamedGroup.BRAINPOOLP256R1);
            case BRAINPOOLP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "7A15487AF637530E2BECC85585C2E36C21447AB4C786F08EF75A1EFBE7785016855AB3B6EFBB9F80517C23C1438A3F18",
                    16),
                    new BigInteger(
                        "1C8AC00FBE2E3CD0994704AC81F8210A283F34D4F351F19525876A14719B8DDAC45315782BB7BBEAB47B0B6061788A9D",
                        16),
                    new BigInteger("5"), NamedGroup.BRAINPOOLP384R1);
            case BRAINPOOLP512R1:
                return new InvalidCurvePoint(new BigInteger(
                    "3A52E57C2D5BE39BB3F97C4CF90D81BEE7123CACBC6B7FF6EB03A164CCF0253FDF1AACF7C4AC6B820E6D48145D7854C67DEF4CADAB555D4609E279956450A610",
                    16),
                    new BigInteger(
                        "1C41E102D5E9EF09CA132E808D87D1C0944951572E82C4F9FECACC80714C0C926E5DA09BD775F5C7E2BE54878EE2AC1A091A8653AE9961789202FD2BA21E7999",
                        16),
                    new BigInteger("5"), NamedGroup.BRAINPOOLP512R1);
            default:
                return null;
        }
    }

    /**
     * Provides an Invalid Curve point with an order that is greater than the order of the point returned by
     * smallOrder(group)
     * 
     * @param  group
     * @return       InvalidCurvePoint
     */
    public static InvalidCurvePoint alternativeOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new InvalidCurvePoint(new BigInteger("1D87BDF3020ECF141B9CCF6CD469670E8391E2C4", 16),
                    new BigInteger("1311274F63434234956CE364DDDAEA82B8656A92", 16), new BigInteger("7"),
                    NamedGroup.SECP160K1);
            case SECP160R1:
                return new InvalidCurvePoint(new BigInteger("2D7A466ED80D9047E8C6D31A53BD96096A57C9A", 16),
                    new BigInteger("8931F5FE3B75A76D77B084D4B9C5AE41F94C55A7", 16), new BigInteger("7"),
                    NamedGroup.SECP160R1);
            case SECP160R2:
                return new InvalidCurvePoint(new BigInteger("7659726CAB152DA1499B6D440F7C59D375765748", 16),
                    new BigInteger("ED4D6EFAEACD74C884D56C8E67CE9219CE9799F2", 16), new BigInteger("7"),
                    NamedGroup.SECP160R2);
            case SECP192K1:
                return new InvalidCurvePoint(new BigInteger("B6CF1A71A6B0DB9B14A54C76D9B31DC0C62046DF3179A165", 16),
                    new BigInteger("A057F8CFDB0D0C84A2A6951877F6D0C764920133CB1121E9", 16), new BigInteger("13"),
                    NamedGroup.SECP192K1);
            case SECP192R1:
                return new InvalidCurvePoint(new BigInteger("222C329BB757B627EFDB51830F1DD74EB357C2319B84EFA6", 16),
                    new BigInteger("5EDF6B98415FB433C0A2B8870E0ACFF8F29261D97E150C05", 16), new BigInteger("7"),
                    NamedGroup.SECP192R1);
            case SECP224K1:
                return new InvalidCurvePoint(
                    new BigInteger("504AF25E468A1DDFBD173146859AD3B33508452D5059CF6EAC45EA42", 16),
                    new BigInteger("C43A7D1FB2D009A17F16565D209C9FB4A7D1E76B0AF29A3BD89BC331", 16),
                    new BigInteger("31"), NamedGroup.SECP224K1);
            case SECP224R1:
                return new InvalidCurvePoint(
                    new BigInteger("338C727BDD4CC6E62302852D16E4B53902BC9A60625933FDC7B8D0E", 16),
                    new BigInteger("1729BFAD9B19FAC33F6F4EFCD02BCE0C37E268EF3E308D2E48773D51", 16), new BigInteger("7"),
                    NamedGroup.SECP224R1);
            case SECP256K1:
                return new InvalidCurvePoint(
                    new BigInteger("D39131C3845D27BD25896B1C5A44579131BD7F0FB888DC7CFF27F9E868F05D20", 16),
                    new BigInteger("73D4222014F2D8D30D9D8495CC7B1CFA4969977F90C304C781C62D260C04E5ED", 16),
                    new BigInteger("13"), NamedGroup.SECP256K1);
            case SECP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("55E964D6B59EAB7398F5FD916DA422A22532F38174DD16AD4124909EBD40C2AD", 16),
                    new BigInteger("9DD16682A1DB35B97E699967D2883A6943EB67C2F9EDF54D7C3CD6ACFEE532CD", 16),
                    new BigInteger("7"), NamedGroup.SECP256R1);
            case SECP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "F52D4B60E5BD66B313C17180B8A24EDC71D7CB01E8C98BCEAF6FCD5205D7621C4D35B3AFBF6FD7F964C9158D98EA5B99",
                    16),
                    new BigInteger(
                        "D30EC40040049F5D948E5C1DB32A2DCD68810D57B4060DCEABE7B47BF65AEF988159262DE0B4FAB67BF7A2B509F07A31",
                        16),
                    new BigInteger("7"), NamedGroup.SECP384R1);
            case SECP521R1:
                return new InvalidCurvePoint(new BigInteger(
                    "DCC0F5B80FF7B8BA940B119984B6BC0B22E23876369CBAD16C760F71420035AE3E790EADF6E19B4CF1A9EC8D68665DBD74F016BE828520BEEFEA7DA33D020FC47B",
                    16),
                    new BigInteger(
                        "1594BF4CFD88E77E8838EE115E1EA3C5D2E66017442993DA9227BB244D30FEAA66ABF8CFADDB9E579E1985834261964FAEE56042740C167F0EB243E5682E0B48BD",
                        16),
                    new BigInteger("7"), NamedGroup.SECP521R1);
            case BRAINPOOLP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("93FAAAB2FC3E9515421D057483FA4F825BFF94631A3D56C3BDBAF73AA1984134", 16),
                    new BigInteger("7F2F16CF0689CDDF098C79201185AF9A1787F94B954C0CA3063B3ECAA4BFF57D", 16),
                    new BigInteger("7"), NamedGroup.BRAINPOOLP256R1);
            case BRAINPOOLP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "210FAB064A624CC3A4F32F703084784B5102D10B34DE8C9284331957466A2C98F01B2DDD90A9F3D1770BF7F133DE6091",
                    16),
                    new BigInteger(
                        "267482AF3B949A7CE742C371AD6EB057EAF9A30005576CC7C43CEEF96F700F952974513B5FEB9A8926445EE041E1777A",
                        16),
                    new BigInteger("7"), NamedGroup.BRAINPOOLP384R1);
            case BRAINPOOLP512R1:
                return new InvalidCurvePoint(new BigInteger(
                    "1D94C4D096486452083C1D7862EC13B34291643A81B4BA1E1F9A05C5D28697DD2B5B5527608590A9B5702AC1486071E6E2C3793570E10868F1BFA017AC6CB99D",
                    16),
                    new BigInteger(
                        "3E3188BD0159231C2475C50C15FC55C1EB1FB4FA0D4F999B911899CB3E9E5F656B5D89C620FCE47AB2481244B931131430EF651FEE08D23D7BD5A85FAC25CD2A",
                        16),
                    new BigInteger("7"), NamedGroup.BRAINPOOLP512R1);
            default:
                return null;
        }
    }

    /**
     * Provides an Invalid Curve point with an order that is far greater than the order of the point returned by
     * smallOrder(group) and alternativeOrder(group).
     * 
     * @param  group
     * @return       InvalidCurvePoint
     */
    public static InvalidCurvePoint largeOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new InvalidCurvePoint(new BigInteger("4D7CFB5017AB4A1A3961246D26CB12B908BDDD9C", 16),
                    new BigInteger("794884B1B0FDE7DC6F2F82AFE4353933318CD524", 16),
                    new BigInteger("759948073135831273703554930117"), NamedGroup.SECP160K1);
            case SECP160R1:
                return new InvalidCurvePoint(new BigInteger("9FDE9461895EF138EE21D3C94238A5A2B745E2DA", 16),
                    new BigInteger("5D36BA39DC089A43DA60ACF9FAB4F8C0A39D4C3", 16),
                    new BigInteger("4191613672177535554053499360049"), NamedGroup.SECP160R1);
            case SECP160R2:
                return new InvalidCurvePoint(new BigInteger("B3F4B6E3D06FF19098F49263E8D7FC34672E18B9", 16),
                    new BigInteger("2475E9826AEE03775E9B938D2F50A1B616D2402F", 16),
                    new BigInteger("27775205518255473578517839"), NamedGroup.SECP160R2);
            case SECP192K1:
                return new InvalidCurvePoint(new BigInteger("F734BE0E63B102ED74D5DB28285AC7E7BC70EBA1B53270AE", 16),
                    new BigInteger("81CF4C441806F65DCD966B349984089E5001E8E2BCAE8C1", 16),
                    new BigInteger("60231627103175743"), NamedGroup.SECP192K1);
            case SECP192R1:
                return new InvalidCurvePoint(new BigInteger("625CCE1305788A185AA2486C50CA37A7C229FBDEAE6DE41C", 16),
                    new BigInteger("5EF2D35652D26A0505B13E4D5A833AA8E9623D116752334E", 16),
                    new BigInteger("46532316352815299146823531531060011"), NamedGroup.SECP192R1);
            case SECP224K1:
                return new InvalidCurvePoint(
                    new BigInteger("DA762C8EFD666A6ECD7B67F7AAA9ED0D641A4C376BA0E5E4CED62B9C", 16),
                    new BigInteger("4D9274FF2316656B06945AD4E1F227A6850BB6E6157FC7853704E5F1", 16),
                    new BigInteger("124289311"), NamedGroup.SECP224K1);
            case SECP224R1:
                return new InvalidCurvePoint(
                    new BigInteger("75D3194E237B0F3927FB15420FFAA34752F27C599A7E4A99799C262F", 16),
                    new BigInteger("AA962E5A2DEC7090FBCA62C637EF23E5E940283535D90193CA57B1A", 16),
                    new BigInteger("96297495373"), NamedGroup.SECP224R1);
            case SECP256K1:
                return new InvalidCurvePoint(
                    new BigInteger("3DC31FF57D07714E0CBD27549E123897065F40D030398A02308E6BDB3A83F898", 16),
                    new BigInteger("E312B9436F6E23676A8FCBCE0CE4283F39395AD5A6FD15E9446F1B29A9BC9C71", 16),
                    new BigInteger("22921299619447"), NamedGroup.SECP256K1);
            case SECP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("6BACBD65749F99750E1BE0A2E94766BE0C59C173B7DE6BF2721726D17A4B22D5", 16),
                    new BigInteger("8578AF52DA5BD23DA9E99A82E4D5F059B1A4AB1E9516F34858908D032EFB282E", 16),
                    new BigInteger("24859202477"), NamedGroup.SECP256R1);
            case SECP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "8D1742D10F93605969D722A9D593B6970F3C657C15395E493D338A1B975F472937E5C1A0B0497E60EC873D13080EA56A",
                    16),
                    new BigInteger(
                        "5517B21BCE588E9CCC213B6A742337FE73AAEF7461BAEF44B3329C5624D3D75C06FA18FA2E8A973F1CD300EBD6DB291A",
                        16),
                    new BigInteger("92357"), NamedGroup.SECP384R1);
            case SECP521R1:
                return new InvalidCurvePoint(new BigInteger(
                    "7DD80045EC25DADE67B3229ED1E956E787BC76535464BAB34B89F351CFC6F9339AC19E97BB335EDABB472817347FCEBC3BB491D857592E77B715F64DB744FC14FD",
                    16),
                    new BigInteger(
                        "10145A33480F884AAC5319CFD480D7E8F65E7F56094892B0697093162484C23EF6EDEC90AE9313DF8B28A5E7F1FE8E03C4A761B074F06FB3F58C379184B765DD97F",
                        16),
                    new BigInteger("92987"), NamedGroup.SECP521R1);
            case BRAINPOOLP256R1:
                return new InvalidCurvePoint(
                    new BigInteger("268FEFC699BFA00D2F6ED0EC0011414D83042E3240D14829369BA07B2B88EB81", 16),
                    new BigInteger("A84D6A486D63750D6BBFEECD5D216EBBD27356C05A1FA93E91A23C6CBEB336D", 16),
                    new BigInteger("18990711710621799596999906783"), NamedGroup.BRAINPOOLP256R1);
            case BRAINPOOLP384R1:
                return new InvalidCurvePoint(new BigInteger(
                    "7D82BD045242FE9D69B4051BF57C4B77FD6E4DC980DF8B11AA6024C9BE7371AB609FE4C0F310A7ECEAFAACE74998FD11",
                    16),
                    new BigInteger(
                        "92D8B30A7582A15754017CC7319C96F43ADFFBB64D16C844EA4FA3667D02ED75F42C0A91EE2947F5CA0E9FED4E2CDDD",
                        16),
                    new BigInteger("86531"), NamedGroup.BRAINPOOLP384R1);
            case BRAINPOOLP512R1:
                return new InvalidCurvePoint(new BigInteger(
                    "99291D9A7F2D0FDBF4127F97A505EA1CF59EAF17305C55AC78CB1AFF3CB51F1FD88EDDA2C0DB05E3785A0BA0E39D72215FAE8DC5D6CA6DCDF7ADF6183D1CA2F7",
                    16),
                    new BigInteger(
                        "4110F07371C82AEC725E180E7BA55C6523DD8C63842BBC0A48AFD10798B4251B62AD79580129F0DFF0D66BE0FE6A625B7DCF91DBEC6B6A705E0EC20673819AD6",
                        16),
                    new BigInteger("3757915019513500970791"), NamedGroup.BRAINPOOLP512R1);
            default:
                return null;
        }
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
     *                         the publicPointBaseX to set
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
     *                         the publicPointBaseY to set
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @param order
     *              the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }
}
