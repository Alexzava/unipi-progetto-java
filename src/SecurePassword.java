/*
 *  Github: https://github.com/alexzava/unipi-progetto-java
 *
 *  License: Apache License 2.0
 *
 */

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

class SecurePassword {
    private byte[] encrypted_password;
    private byte[] salt_bytes;

    //PBKDF2 Settings
    private int iterations = 5000;
    private int key_length = 512;
    private int salt_length = 64;

    /*
     *   OVERVIEW: Genera una password sicura utilizzando le impostazioni predefinite
     *   REQUIRES: plain_password != null, plain_password != ""
     *   MODIFIES: this
     *   EFFECTS: Genera una password sicura utilizzando le impostazioni predefinite
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, plain_password non contiene almeno un carattere (Unchecked)
     */
    public SecurePassword(String plain_password) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException {
        if(plain_password == null)
            throw new NullPointerException();

        if(plain_password == "")
            throw new IllegalArgumentException("plain_password deve contenere almeno un carattere");

        this.salt_bytes = new byte[this.salt_length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(this.salt_bytes);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(plain_password.toCharArray(), this.salt_bytes, this.iterations, this.key_length);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);

        this.encrypted_password = secretKey.getEncoded();
    }

    /*
     *   OVERVIEW: Genera una password sicura utilizzando le impostazioni personalizzate
     *   REQUIRES:
     *      plain_password != null, plain_password != ""
     *      iterations != null, iterations >= 1000
     *      key_length != null, key_length >= 128
     *      salt_length != null, salt_length >= 16
     *   MODIFIES: this
     *   EFFECTS: Genera una password sicura utilizzando le impostazioni personalizzate
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando plain_password non contiene almeno un carattere (Unchecked)
     *      InvalidSizeException, quando la grandezza inserita non è valida (iterations < 1000, key_length < 128, salt_length < 16) (Checked)
     */
    public SecurePassword(String plain_password, int iterations, int key_length, int salt_length) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException, InvalidSizeException {
        if(plain_password == null)
            throw new NullPointerException();

        if(plain_password == "")
            throw new IllegalArgumentException("plain_password deve contenere almeno un carattere");

        if(iterations < 1000 || key_length < 128 || salt_length < 16)
            throw new InvalidSizeException("iterations deve essere >= 1000, key_length deve essere >= 128, salt_length deve essere >= 16");

        this.iterations = iterations;
        this.key_length = key_length;
        this.salt_length = salt_length;

        this.salt_bytes = new byte[salt_length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(this.salt_bytes);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(plain_password.toCharArray(), salt_bytes, iterations, key_length);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);

        this.encrypted_password = secretKey.getEncoded();
    }

    /*
     *   OVERVIEW: Verifica se la password inserita coincide con la password cifrata
     *   REQUIRES: plain_password != null, plain_password != ""
     *   MODIFIES:
     *   EFFECTS: Ritorna true se la password inserita coincide con quella cifrata, altrimenti false se le password non corrispondono
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando plain_password non contiene almeno un carattere (Unchecked)
     *
     */
    public boolean verify_password(String plain_password) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException {
        if(plain_password == null)
            throw new NullPointerException();

        if(plain_password == "")
            throw new IllegalArgumentException("plain_password deve contenere almeno un carattere");

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(plain_password.toCharArray(), this.salt_bytes, this.iterations, this.key_length);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);

        if(Arrays.equals(this.encrypted_password, secretKey.getEncoded()))
            return true;
        else
            return false;
    }

    /*
     *   OVERVIEW: Ritorna la password cifrata
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna un byte array contenente la password cifrata
     *   THROWS:
     *
     */
    public byte[] getEncrypted_password() {
        return encrypted_password;
    }

    /*
     *   OVERVIEW: Ritorna i salt bytes
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna un byte array contenente i salt utilizzati
     *   THROWS:
     *
     */
    public byte[] getSalt_bytes() {
        return salt_bytes;
    }

    /*
     *   OVERVIEW: Ritorna la lunghezza di salt in byte
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna la lunghezza di salt in byte
     *   THROWS:
     *
     */
    public int getSalt_length() {
        return salt_length;
    }

    /*
     *   OVERVIEW: Ritorna il numero di iterazioni impostate
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna il numero di iterazioni impostate
     *   THROWS:
     *
     */
    public int getIterations() {
        return iterations;
    }

    /*
     *   OVERVIEW: Ritorna la lunghezza della password cifrata in bit
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna la lunghezza della password cifrata in bit
     *   THROWS:
     *
     */
    public int getKey_length() {
        return key_length;
    }
}
