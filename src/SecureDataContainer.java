/*
 *  Github: https://github.com/alexzava/unipi-progetto-java
 *
 *  License: Apache License 2.0
 *
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

public interface SecureDataContainer<E> {
    /*
     *   OVERVIEW: Crea l’identità di un nuovo utente della collezione
     *   REQUIRES: id, passw != null e id, pass != ""
     *   MODIFIES: this
     *   EFFECTS: Crea l’identità di un nuovo utente della collezione credentials
     *   THROWS:
     *           InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *           NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *           IllegalArgumentException, quando id e passw non contengono almeno un carattere (Unchecked)
     *           NullPointerException, quando un elemento è nullo (Unchecked)
     *           UsernameNotAvailableException, quando l'utente è già registrato (Checked)
     */
    public void createUser(String id, String passw) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidSizeException, UsernameNotAvailableException;

    /*
     *   OVERVIEW: Restituisce il numero degli elementi di un utente presenti nella collezione
     *   REQUIRES: owner, passw != null
     *   MODIFIES: 
     *   EFFECTS: Restituisce il numero degli elementi di un utente presenti nella collezione
     *   THROWS:
     *           InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *           NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *           IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *            NullPointerException, quando un elemento è nullo (Unchecked)
     *           InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public int getSize(String owner, String passw) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException;

    /*
     *   OVERVIEW: Inserisce il valore del dato nella collezione se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw, data != null
     *   MODIFIES: this
     *   EFFECTS: Inserisce il valore del dato nella collezione storage
     *   THROWS:
     *           InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *           NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *           IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *           IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *           IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *           InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *           BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *           InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *           NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *            NullPointerException, quando un elemento è nullo (Unchecked)
     *           InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public boolean put(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException;

    /*
     *   OVERVIEW: Ottiene una copia del valore del dato nella collezione se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw, data != null
     *   MODIFIES:
     *   EFFECTS: Ritorna una copia del valore del dato nella collezione storage
     *   THROWS:
     *           InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *           NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *           IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *           IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *           InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *           NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *           BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *           IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *           InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *           ClassNotFoundException, quando si cerca di caricare una classe non definita nell'ambiente (Unchecked)
     *           NoSuchElementException, quando il dato cercato non è presente nella collezione(Unchecked)
     *           NullPointerException, quando un elemento è nullo (Unchecked)
     *           ClassNotFoundException, quando si prova a caricare una classe, che non è presente, tramite una stringa (Unchecked)
     *           InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public E get (String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException;

    /*
     *   OVERVIEW: Rimuove il dato nella collezione se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw, data != null
     *   MODIFIES: this
     *   EFFECTS: Ritorna una copia del dato nella collezione se la rimozione avviene con successo, altrimenti ritorna null
     *   THROWS:
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      NoSuchElementException, quando il dato cercato non è presente nella collezione(Unchecked)
     *      InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public E remove(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException;

    /*
     *   OVERVIEW: Crea una copia del dato nella collezione se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw, data != null
     *   MODIFIES: this
     *   EFFECTS: Crea una copia del dato nella collezione storage
     *   THROWS:
     *           InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *           NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *           IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *           IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *           InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *           NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *           BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *           IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *           InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *           ClassNotFoundException, quando si cerca di caricare una classe non definita nell'ambiente (Unchecked)
     *           NoSuchElementException, quando il dato cercato non è presente nella collezione(Unchecked)
     *            NullPointerException, quando un elemento è nullo (Unchecked)
     *           InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public void copy(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, AlreadyInCollection;

    /*
     *   OVERVIEW: Condivide il dato nella collezione con un altro utente se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw, other, data != null
     *   MODIFIES: this
     *   EFFECTS: Aggiunge l'utente alla lista degli owners del dato fornito
     *   THROWS:
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      ClassNotFoundException, quando si cerca di caricare una classe non definita nell'ambiente (Unchecked)
     *      NoSuchElementException, quando il dato cercato non è presente nella collezione(Unchecked)
     *      NullPointerException, quando un elemento è nullo (Unchecked)
     *      ClassNotFoundException, quando si prova a caricare una classe, che non è presente, tramite una stringa (Unchecked)
     *      InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     *      UsernameNotAvailableException, quando l'utente con cui condividere il dato non esiste (Checked)
     *      AlreadySharedException, quando si vuole condividere un dato già condiviso (Solo seconda implementazionew) (Checked)
     */
    public void share(String owner, String passw, String other, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, UsernameNotAvailableException, AlreadySharedException;

    /*
     *   OVERVIEW: Restituisce un iteratore (senza remove) che genera tutti i dati dell'utente in ordine arbitrario se vengono rispettati i controlli di identità
     *   REQUIRES: owner, passw != null
     *   MODIFIES:
     *   EFFECTS: Resituisce un iteratore (senza remove) che genera tutti i dati dell'utente in ordine arbitrario
     *   THROWS:
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IllegalArgumentException, quando owner e passw non contengono almeno un carattere (Unchecked)
     *      InvalidAlgorithmParameterException, quando viene chiesto di usare un algoritmo non presente nell'ambiente (Unchecked)
     *      IOException, quando le operazioni di input/output non avvengono correttamente (Unchecked)
     *      BadPaddingException, quando un dato ha uno schema di padding differente da quello impostato (Unchecked)
     *      IllegalBlockSizeException, quando il dato fornito non rispetta la lunghezza per il blocco di cifratura (Unchecked)
     *      NoSuchPaddingException, quando viene chiesto di usare un particolare meccanismo di padding non presente nell'ambiente (Unchecked)
     *      InvalidKeyException, quando la chiave di cifratura fornita non è valida. (Codifica errata, lunghezza errata, non inizializzata ecc...) (Unchecked)
     *      ClassNotFoundException, quando si cerca di caricare una classe non definita nell'ambiente (Unchecked)
     *      NullPointerException, quando un elemento è nullo (Unchecked)
     *      ClassNotFoundException, quando si prova a caricare una classe, che non è presente, tramite una stringa (Unchecked)
     *      InvalidAuthenticationException, quando l'autenticazione non è valida (Checked)
     */
    public Iterator<E> getIterator(String owner, String passw) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException;
}
