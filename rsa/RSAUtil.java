import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {

    private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvvqDQhdw+5tYJ4Qo6L2PobQO30XwxsHrC3+Ae2l3Jra2yMxcAcdbemXqKYlN/FVo/+OcaU8+ABdsWoHP7OQh9RVKPz2BjCs+sQF+wCJhAZshwUSbHzd0ypkNB1I4Naq7PnYqQKMn5Mkg9RdsNEV0xdgHba/sHOAqdSUxBFzsqJwIDAQAB";
    private static String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK++oNCF3D7m1gnhCjovY+htA7fRfDGwesLf4B7aXcmtrbIzFwBx1t6ZeopiU38VWj/45xpTz4AF2xagc/s5CH1FUo/PYGMKz6xAX7AImEBmyHBRJsfN3TKmQ0HUjg1qrs+dipAoyfkySD1F2w0RXTF2Adtr+wc4Cp1JTEEXOyonAgMBAAECgYBxS5oOc401u8hWHA5kzjJBHy4bbV/8BIJPaNXp7eoyXtWwIIF+luTnIdg+p/6d2Z0RyprpfQgyxxOjNZMvbGgMjDHqw3jWc7uid6gkt4tkX+glf38/msdLlE1lBrSDhKntm+8msbfLpxOtJ/wPsyHAqfhtUpFyYNBwvRxVBPFiGQJBAP2Dlmx8AJYRU2PI/RlNwmTRAfb1ogr17UACsLOCtZMuaNpd/1n58Qa2bNJvKo17Z0CoL2QRWPQowB34F8zIJW0CQQCxd8+o1Ma43KFfKcfPmy21NDc1admW62CMLwXwoIpQmCJUTul/tI6GL0UsasQJH6N3gV1jGEPbH7bN7IpH1dVjAkEA6DwXHKIr101f2tVQJlH5dmmRJy61ltzazfyo6oke1Ql6vC/HsCErDz8mSU/U527Yk35+i2jo2CJMfCe9hbcDsQJBAKtkN4QpAka0pZCfbB5/EpSm+g62zHKpnZOlMkpi8VHGq5jaoT05ZlAHRPoRnoPlL10R7dvvKlFsfoK/yAh6ZlsCQCmQd6mG9dMg4gLwgQklcrnzG/nTJO2f2TB15FFtR5wTqVvDyJOAR5zUsVwzOC6MwuUKrDD1biT7R8qBSvKjk7c=";

    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static void main(String[] args)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("Dhiraj is the author", publicKey));
            System.out.println(encryptedString);
            String decryptedString = RSAUtil.decrypt(encryptedString, privateKey);
            System.out.println(decryptedString);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }

    }
}
