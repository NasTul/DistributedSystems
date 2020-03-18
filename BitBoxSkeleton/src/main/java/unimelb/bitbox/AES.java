package unimelb.bitbox;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


/**
 * @author Administrator
 */
public class AES {

    //  encryption
    public static String Encrypt(String sSrc, String sKey) throws Exception {
        if (sKey == null) {
            System.out.print("Key is null");
            return null;
        }
        // Determine whether the Key is 16-bit
        if (sKey.length() != 16) {
            System.out.print("Key length is not 16byte");
            return null;
        }
        byte[] raw = sKey.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//"Algorithm/mode/complement mode"
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));

        return new Base64().encodeToString(encrypted);//BASE64 is used here as transcoding function, and it can play the role of twice encryption.
    }

    // 解密
    public static String Decrypt(String sSrc, String sKey) throws Exception {
        try {
            // Determine if the Key is correct
            if (sKey == null) {
                System.out.print("Key is null");
                return null;
            }
            // Determine whether the Key is 16-bit
            if (sKey.length() != 16) {
                System.out.print("Key length is not 16byte");
                return null;
            }
            byte[] raw = sKey.getBytes("utf-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] encrypted1 = new Base64().decode(sSrc);//先用base64解密
            try {
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "utf-8");
                return originalString;
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        /*
         * 此处使用AES-128-ECB加密模式，key需要为16位。
         */
        String cKey = "1234567890123456";
        // 需要加密的字串
        String cSrc = "www.gowhere.so";
        System.out.println(cSrc);
        // 加密
        String enString = AES.Encrypt(cSrc, cKey);
        System.out.println("after encode：" + enString);

        // 解密
        String DeString = AES.Decrypt(enString, cKey);
        System.out.println("after decode：" + DeString);
    }
}

