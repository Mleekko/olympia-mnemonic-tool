package com.mleekko;

import com.radixdlt.crypto.ECKeyPair;
import com.radixdlt.crypto.ECKeyUtils;
import com.radixdlt.crypto.exception.PrivateKeyException;
import com.radixdlt.crypto.exception.PublicKeyException;
import com.radixdlt.identifiers.REAddr;
import com.radixdlt.networks.Addressing;
import com.radixdlt.networks.Network;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class XRD_PrivateKeyToAddress {

    private static final List<ChildNumber> path = Arrays.asList(
            new ChildNumber(44, true),
            new ChildNumber(1022, true),
            ChildNumber.ZERO_HARDENED,
            ChildNumber.ZERO,
            null
    );

    public static void main(String[] args) throws PrivateKeyException, PublicKeyException {
        System.out.println("Prompting for mnemonic...");
        String MNEMONIC = javax.swing.JOptionPane.showInputDialog("Enter your mnemonic phrase.");

        byte[] seedBytes = org.bitcoinj.crypto.PBKDF2SHA512.derive(MNEMONIC, "mnemonic", 2048, 64);

        DeterministicKey rootKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);
        rootKey.setCreationTimeSeconds(0);
        DeterministicHierarchy hierarchy = new DeterministicHierarchy(rootKey);


        int count = 10;
        System.out.println("Your first 10 accounts: ");
        System.out.println("Private key                                                      -> Olympia address");
        for (int i = 0; i < count; i++) {
            path.set(4, new ChildNumber(i, true));
            DeterministicKey keyByPath = hierarchy.get(path, false, true);
            BigInteger privKey = keyByPath.getPrivKey();

            byte[] privateKey = ECKeyUtils.adjustArray(privKey.toByteArray(), 32);
            String account = getAddrFromPrivateKey(privateKey);
            String privateKeyHex = Hex.toHexString(privateKey);
            System.out.println(privateKeyHex + " -> " + account);
        }

        System.out.println();
        System.out.println("DOES THIS MATCH ACCOUNTS IN THE WALLET?");
        System.out.println();
        System.out.println("If so,");
        System.out.println("1. Put your private key in `_IN/oprivate-key.txt`.");
        System.out.println("2. Put your Olympia address in `_IN/olympia-address.txt`.");
        System.out.println("3. Delete the mnemonic words from this file.");

    }

    static String getAddrFromPrivateKey(byte[] privateKey) throws PrivateKeyException, PublicKeyException {
        ECKeyPair ecKeyPair = ECKeyPair.fromPrivateKey(privateKey);

        Addressing addressing = Addressing.ofNetwork(Network.MAINNET);
        REAddr addr = REAddr.ofPubKeyAccount(ecKeyPair.getPublicKey());
        return addressing.forAccounts().of(addr);
    }

    /*
            String privateKeyHex = "80834f88da19f32dcf99eab9ee2f76682b3e85787fdf0934b8f7777777777777";

        byte[] privateKey = Hex.decode(privateKeyHex);

        String account = getAddrFromPrivateKey(privateKey);

        System.out.println("Your Olympia account: " + account);
     */
}
