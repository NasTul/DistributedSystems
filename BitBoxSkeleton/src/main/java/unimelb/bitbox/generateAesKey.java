package unimelb.bitbox;
import java.security.SecureRandom;
import java.util.Random;

public class generateAesKey {

    public generateAesKey() {
    }

    /**
     * Generate 16 bits of non - repeating random Numbers, including Numbers + case
     *
     * @return
     */
    public static String getRandom16() {
        StringBuilder uid = new StringBuilder();
        //Generates strong 16-bit random Numbers
        Random rd = new SecureRandom();
        for (int i = 0; i < 16; i++) {
            //Generates 3-bit random Numbers from 0 to 2
            int type = rd.nextInt(3);
            switch (type) {
                case 0:

                    uid.append(rd.nextInt(10));
                    break;
                case 1:
                    //ASCII Between 65 and 90 is upper case, get upper case random
                    uid.append((char) (rd.nextInt(25) + 65));
                    break;
                case 2:
                    //ASCII Is lowercase between 97 and 122, get lowercase random
                    uid.append((char) (rd.nextInt(25) + 97));
                    break;
                default:
                    break;
            }
        }
        return uid.toString();
    }

}

