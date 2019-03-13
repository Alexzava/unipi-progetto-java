/*
 *  Github: https://github.com/alexzava/unipi-progetto-java
 *
 *  License: Apache License 2.0
 *
 */

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class SecureDataInfo<E> {

    //Impostazioni chiave di cifratura AES
    private int encKey_iterations = 5000;
    private int encKey_size = 128;

    //Impostazioni di cifratura AES
    private byte[] saltBytes = new byte[64];
    private byte[] IV = new byte[12];

    private List<String> owners = new ArrayList<>();
    private byte[] encryptedValue;
    private byte[] hash;
    private E value;

    private boolean isEncrypted;

    /*
     *   OVERVIEW: Crea l'oggetto cifrando il dato fornito
     *   REQUIRES: owner, value, password != null, owner, password != ""
     *   MODIFIES: this
     *   EFFECTS: Crea l'oggetto cifrando il dato fornito e calcola l'hash del dato non cifrato
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public SecureDataInfo(String owner, E value, String password) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalArgumentException {
        if(owner == null || value == null || password == null)
            throw new NullPointerException();

        if(owner.equals("") || password.equals(""))
            throw new IllegalArgumentException("owner e password devono contenere almeno un carattere");

        this.owners.add(owner);
        this.hash = generateHash(value);
        this.encryptedValue = encryptData(value, password);
        this.isEncrypted = true;
        this.value = null;
    }

    /*
     *   OVERVIEW: Crea l'oggetto senza cifrare il dato fornito
     *   REQUIRES: owner, value != null, owner != ""
     *   MODIFIES: this
     *   EFFECTS: Crea l'oggetto senza cifrare il dato fornito e calcola l'hash del dato non cifrato
     *   THROWS:
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchAlgorithmException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *
     */
    public SecureDataInfo(String owner, E value) throws IOException, NoSuchAlgorithmException {
        if(owner == null || value == null)
            throw new NullPointerException();

        if(owner.equals(""))
            throw new IllegalArgumentException("owner deve contenere almeno un carattere");

        this.owners.add(owner);
        this.hash = generateHash(value);
        this.value = value;
        this.isEncrypted = false;
        this.encryptedValue = null;
    }

    /*
     *   OVERVIEW: Aggiunge un nuovo owner al dato
     *   REQUIRES: owner != null, owner != ""
     *   MODIFIES: this
     *   EFFECTS: Aggiunge un nuovo owner alla lista owners del dato
     *   THROWS:
     *
     */
    public void addOwner(String owner) {
        if(!this.owners.contains(owner))
            this.owners.add(owner);
    }

    /*
     *   OVERVIEW: Ritorna il dato
     *   REQUIRES: password != null, password != ""
     *   MODIFIES:
     *   EFFECTS: Se il dato è cifrato ritorna una copia del dato decifrato, altrimenti ritorna il dato non cifrato
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     *
     */
    public E getValue(String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, ClassNotFoundException {
        if(password == null)
            throw new NullPointerException();

        if(password.equals(""))
            throw new IllegalArgumentException("password deve contenere almeno un carattere");

        if(isEncrypted)
            return decryptData(password);
        else
            return this.value;
    }

    /*
     *   OVERVIEW: Ritorna una copia della lista degli owners del dato
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna una copia della lista degli owners del dato
     *   THROWS:
     *
     */
    public List<String> getOwners() {
       List<String> result = new ArrayList<>(owners);
       return result;
    }

    /*
     *   OVERVIEW: Ritorna l'hash del dato non cifrato
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna un byte array contenente l'hash del dato non cifrato
     *   THROWS:
     *
     */
    public byte[] getHash() {
        return hash;
    }

    /*
     *   OVERVIEW: Ritorna l'informazione se il dato è cifrato o in chiaro
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritona true se il dato è cifrato, altrimenti false se il dato non è cifrato
     *   THROWS:
     *
     */
    public boolean isEncrypted(){
        return this.isEncrypted;
    }

    /*
     *   OVERVIEW: Decifra il dato in modo irreversibile
     *   REQUIRES: password != null, password != ""
     *   MODIFIES: this
     *   EFFECTS: Decifra il dato in modo irreversibile
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     *      ClassNotFoundException, quando si prova a caricare una classe, che non è presente, tramite una stringa (Unchecked)
     *
     */
    public void makePublic(String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, ClassNotFoundException {
        if(password == null)
            throw new NullPointerException();

        if(password.equals(""))
            throw new IllegalArgumentException("password deve contenere almeno un carattere");

        this.value = decryptData(password);
        this.isEncrypted = false;
    }

    /*
     *   OVERVIEW: Genera l'hash di un dato
     *   REQUIRES: value != null
     *   MODIFIES:
     *   EFFECTS: Ritorna un byte array contenente l'hash del dato fornito
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *
     */
    private byte[] generateHash(E value) throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutput objectOutput = new ObjectOutputStream(outputStream);
        objectOutput.writeObject(value);
        objectOutput.flush();
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(outputStream.toByteArray());
    }

    /*
     *   OVERVIEW: Cifra il dato fornito tramite l'algoritmo AES con modalità GCM
     *   REQUIRES: value, password != null, password != ""
     *   MODIFIES: this
     *   EFFECTS: Ritorna un byte array contenente il dato cifrato
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     *
     */
    private byte[] encryptData(E value, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        //Genera del Salt Bytes random
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(this.saltBytes);

        //Genera la chiave di cifratura
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), this.saltBytes, this.encKey_iterations, this.encKey_size);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);

        //Genera un IV random
        secureRandom.nextBytes(this.IV);

        //Impostazioni cifrario AES
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, this.IV));

        //Cifra
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutput objectOutput = new ObjectOutputStream(outputStream);
        objectOutput.writeObject(value);
        objectOutput.flush();
        return cipher.doFinal(outputStream.toByteArray());
    }

    /*
     *   OVERVIEW: Decifra il dato tramite l'algoritmo AES con modalità GCM
     *   REQUIRES: password != null, password != ""
     *   MODIFIES:
     *   EFFECTS: Ritorna il dato non cifrato
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     *      ClassNotFoundException, quando si prova a caricare una classe, che non è presente, tramite una stringa (Unchecked)
     *
     */
    private E decryptData(String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {
        //Genera la chiave di cifratura
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), this.saltBytes, this.encKey_iterations, this.encKey_size);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);

        //Impostazioni cifrario AES
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, this.IV));

        //Decifra
        byte[] decrypted = cipher.doFinal(this.encryptedValue);

        //Converte i bytes decifrati nell'oggetto E
        ByteArrayInputStream inputStream = new ByteArrayInputStream(decrypted);
        ObjectInput objectInput = new ObjectInputStream(inputStream);
        return (E) objectInput.readObject();
    }
}
