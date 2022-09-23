import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.StringJoiner;

public class SHA56WithRSA {

    private static final String batchId = "CIT-128187-34";
    private static final String debtorAgent = "2501";
    private static final String getDebtorBranch = "53";
    private static final String debtorAccount = "0530030072000016";
    private static final String batchAmount = "10";
    private static final String batchCrncy = "NPR";

    private static final String instructionId = "CIT-128187-34-1";
    private static final String appId = "CIT-151-APP-2";
    private static final String refId = "6169658";
    private static final String npiUser = "CELLCOM@999";
    private static final String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALTT1baCTiijvH12s8XwQAYFfyRtrgvCcuo9h+HyKbycrme3+ES8WICDMJR8ChbiI0wfrOD+reeG+qFpxr1gqtdmkWWqzFmfFHZc5nMl0wdet6crU3krKArEqUnHpUQ5S0LbcbDM2ysx5crMCnb/72UWc/Ci2Jyf5oVxjn0p7j2rAgMBAAECgYEAsH4qE67vVl8p9FNNeB7cfoQS6p1ayQOLYfGYlQHllsBewcEgQwaKYzSoz+SZfGhQB1bLR/eMCXUHX1B8uA6H73iS89lbJWK9M41y2VZMoA2FNH295HKXmnvbJmGJiocwCtWqW97gSluak5rpwbBMbSQnKVAJpHQhuNVfbe5irnECQQD7L67MKKBBr/ngYo7JzWOKF2VV7M18T8/bjK7pqGggc0VN1F4G0oUFIi6ytgBRFbNdgTLPGdVWAF2GzGic5RWtAkEAuEr4+b73s8/k6EJDE8KBw45Pw+Trw1nxVnF7KNgEE0tjPYkEtg6A1+xc0cIq3+A+c24Y4PLLz92STh8yT7ybtwJBAKa7Wf3uoaG4m9bT1RAjI4WQThWhICz6FXEYiypSPPv9R+2Hn/pLVzy3GeRKZx9rlinlDsLl1PRHPc2ydWZfsekCQFiN1fMTuyyQ0dp0tIyTIw1XnaZwooT8/AVghCCNI/AtgmM4KqZcc7bNYZB9L2Lh+sA2gAffQuX//uRBA0jjRSMCQGGQg8DID6n05wVIPY7IgJak5cJCZSzIWGsZbZLrsDrPIADnyxN9bmCpdwsaiqV/wM1j212CF1WRQE4eeED57aM=";

    public static void main(String[] args) throws SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        StringJoiner batchString = new StringJoiner(",");
        batchString.add(batchId);
        batchString.add(debtorAgent);
        batchString.add(getDebtorBranch);
        batchString.add(debtorAccount);
        batchString.add(batchAmount);
        batchString.add(batchCrncy);

        StringJoiner transactionString = new StringJoiner(",");
        transactionString.add(instructionId);
        transactionString.add(appId);
        transactionString.add(refId);

        String token = batchString.toString() + "," + transactionString.toString() + ","
                + npiUser;

        System.out.println("String token: " + token);

        //sign token with NCHL private key
        String generateToken = signUsingPrivateKey(token, privateKey);

        System.out.println("Generated token: " + generateToken);
    }

    private static String signUsingPrivateKey(String plainText, String privateKeyString)
            throws SignatureException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = generatePrivateKeyFromString(privateKeyString);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);

    }

    private static PrivateKey generatePrivateKeyFromString(String encodedPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);
    }


}
