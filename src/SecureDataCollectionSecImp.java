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
import java.util.*;

/*

Funzione di astrazione:
    <credentials, storage> -->
    <{(String, UserCredentials)0,...,(String, UserCredentials)n}, {(String, SecureDataInfo)0,...,(String, SecureDataInfo)k}> -->
    dove UserCredentials contiene la password e una lista di hash dei dati appartenenti all'utente &&
    SecureDataInfo è composto sostanzialmente dal dato cifrato. -->
    n = credentials.size() && k = storage.size()

Invariante di rappresentazione:
    credentials != null, storage != null &&
    forall(k,y appartenente a credentials.getAllKeys()).(k != null && k != y) => (credentials.get(k) != null)
    forall(h,x appartenente a storage.getAllKeys()).(h != null && h != y)

*/
public class SecureDataCollectionSecImp<E> implements SecureDataContainer<E> {

    //Gli hash vengono codificati in String Base64 perchè non può essere usato un byte array come chiave per una HashMap
    //La struttura dell'hash è hash.username o nel caso di un dato condiviso hash.shared

    private HashMap<String, UserCredentials> credentials = new HashMap<>();
    private HashMap<String, SecureDataInfo<E>> storage = new HashMap<>();

    /*
     *   OVERVIEW: Crea l’identità di un nuovo utente della collezione
     */
    @Override
    public void createUser(String id, String passw) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, UsernameNotAvailableException {
        if(id == null || passw == null)
            throw new NullPointerException();

        if(id.equals("") || passw.equals(""))
            throw new IllegalArgumentException("id e passw devono contenere almeno un carattere");

        //Controlla se l'utente è gia stato registrato
        if(credentials.containsKey(id))
            throw new UsernameNotAvailableException("Utente già registrato");

        //Registra il nuovo utente
        UserCredentials userCredentials = new UserCredentials(passw);
        credentials.put(id, userCredentials);
    }

    /*
     *   OVERVIEW: Restituisce il numero degli elementi di un utente presenti nella collezione
     */
    @Override
    public int getSize(String owner, String passw) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException {
        if(owner == null || passw == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            return credentials.get(owner).getAllElementsHash().size();
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Inserisce il valore del dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public boolean put(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            SecureDataInfo<E> element = new SecureDataInfo<>(owner, data, passw);
            String hash = Base64.getEncoder().encodeToString(element.getHash())+ "." + owner;

            if(credentials.get(owner).addElementHash(hash))
            {
               if(storage.put(hash, element) == null)
                   return true;
               else
                   return false;
            }
            else
               return false;
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Ottiene una copia del valore del dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public E get(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            String hash = Base64.getEncoder().encodeToString(new SecureDataInfo<>(owner, data).getHash()) + "." + owner;

            //Se non esiste un hash, genera l'hash per la versione condivisa
            if(!credentials.get(owner).elementExist(hash))
                hash = hash.replace("."+owner, ".shared");

            //Controlla se il dato appartiene all'utente
            if(credentials.get(owner).elementExist(hash))
                return storage.get(hash).getValue(passw); //Ritorna il dato decifrato
            else
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
                throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Rimuove il dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public E remove(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            String hash = Base64.getEncoder().encodeToString(new SecureDataInfo<E>(owner, data).getHash()) + "." + owner;

            //Se non esiste un hash, genera l'hash per la versione condivisa
            if(!credentials.get(owner).elementExist(hash))
                hash = hash.replace("."+owner, ".shared");

            //Controlla se il dato appartiene all'utente
            if(credentials.get(owner).elementExist(hash))
            {
                credentials.get(owner).removeElementHash(hash);

                //Controlla se il dato è privato o pubblico, se pubblico elimina il dato per tutti gli utenti con cui è condiviso
                if(!storage.get(hash).isEncrypted())
                {
                    for(Map.Entry<String, UserCredentials> entry : credentials.entrySet())
                    {
                        if(entry.getValue().elementExist(hash))
                            credentials.get(entry.getKey()).removeElementHash(hash);
                    }
                }
                return storage.remove(hash).getValue(passw);
            }
            else
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Crea una copia del dato nella collezione se vengono rispettati i controlli di identità. Può essere copiato nella propria collezione soltanto un dato condiviso
     */
    @Override
    public void copy(String owner, String passw, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, AlreadyInCollection {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            String hash = Base64.getEncoder().encodeToString(new SecureDataInfo<>(owner, data).getHash()) + ".shared";

            //Controlla se il dato è accessibile dall'utente ed è condiviso
            if(credentials.get(owner).elementExist(hash))
            {
                //Crea una copia non cifrata del dato. Tutti i dati condivisi non sono cifrati
                hash = hash.replace(".shared", "." + owner);
                SecureDataInfo<E> copyElement = new SecureDataInfo<>(owner, data);

                //Aggiunge il dato alla collezione
                credentials.get(owner).addElementHash(hash);
                storage.put(hash, copyElement);
            }
            else if (credentials.get(owner).elementExist(hash.replace(".shared", "." + owner))) //Se il dato è gia presente nella collezione dell'utente
                throw new AlreadyInCollection("Il dato è già presente nella collezione dell'utente");
            else
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Condivide il dato nella collezione con un altro utente se vengono rispettati i controlli di identità
     */
    @Override
    public void share(String owner, String passw, String other, E data) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, UsernameNotAvailableException, AlreadySharedException {
        if(owner == null || passw == null || other == null || data == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            //Controlla se l'utente con cui condividere il dato esiste
            if(!credentials.containsKey(other))
                throw new UsernameNotAvailableException("L'utente " + other + " non esiste");

            String hash = Base64.getEncoder().encodeToString(new SecureDataInfo<>(owner, data).getHash()) + "." + owner;

            //Controllo che il dato non sia già stato condiviso
            if(storage.containsKey(hash.replace("."+owner, ".shared")))
                throw new AlreadySharedException("L'elemento è già stato condiviso");

            //Controlla se il dato appartiene all'utente
            if(credentials.get(owner).elementExist(hash))
            {
                //Decifra il dato in modo irreversibile
                storage.get(hash).makePublic(passw);

                //Cambia l'hash del dato sostituendo la chiave
                String newHash = hash.replace("." + owner, ".shared");
                SecureDataInfo<E> tmpData = storage.get(hash);
                storage.put(newHash, tmpData);
                storage.remove(hash);

                //Condivide il dato
                credentials.get(other).addElementHash(newHash);
            }
            else
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Restituisce un iteratore (senza remove) che genera tutti i dati dell'utente in ordine arbitrario se vengono rispettati i controlli di identità
     */
    @Override
    public Iterator<E> getIterator(String owner, String passw) throws InvalidAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException {
        if(owner == null || passw == null)
            throw new NullPointerException();

        //Autentica l'utente
        if(credentials.containsKey(owner) && credentials.get(owner).checkPassword(passw))
        {
            List<E> iter_list = new ArrayList<>();
            List<String> elementsHash = credentials.get(owner).getAllElementsHash();
            for(String hash : elementsHash) {
                iter_list.add(storage.get(hash).getValue(passw));
            }
            return Collections.unmodifiableList(iter_list).iterator();
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }
}

//Classe di supporto per le credenziali dell'utente (Solo seconda implementazione)
class UserCredentials {
    private SecurePassword encryptedPassword;
    //Gli hash sono salvati con codifica Base64
    private List<String> hashStrings = new ArrayList<>();

    /*
     *   OVERVIEW: Crea l'oggetto cifrando la password
     *   REQUIRES: password != null, password != ""
     *   MODIFIES: this
     *   EFFECTS: Crea l'oggetto cifrando la password
     *   THROWS:
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public UserCredentials(String password) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException {
        if(password == null)
            throw new NullPointerException();

        if(password.equals(""))
            throw new IllegalArgumentException("password deve contenere almeno un carattere");

        this.encryptedPassword = new SecurePassword(password);
    }

    /*
     *   OVERVIEW: Verifica se la password inserita coincide con la password cifrata
     *   REQUIRES: password != null, password != ""
     *   MODIFIES:
     *   EFFECTS: Ritorna true se la password inserita coincide con quella cifrata, altrimenti false se la password non coincide
     *   THROWS:
     *      InvalidKeySpecException, quando le specifiche per l'oggetto KeySpec non sono valide (Unchecked)
     *      NoSuchAlgorithmException, quando viene chiesto di usare un algoritmo di crittografia non presente nell'ambiente (Unchecked)
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public boolean checkPassword(String password) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException {
        if(password == null)
            throw new NullPointerException();

        if(password.equals(""))
            throw new IllegalArgumentException("password deve contenere almeno un carattere");

        return this.encryptedPassword.verify_password(password);
    }

    /*
     *   OVERVIEW: Aggiunge un hash alla lista
     *   REQUIRES: hash != null, hash != ""
     *   MODIFIES: this
     *   EFFECTS: Aggiunge un nuovo hash alla lista hashStrings
     *   THROWS:
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public boolean addElementHash(String hash) throws IllegalArgumentException {
        if(hash == null)
            throw new NullPointerException();

        if(hash.equals(""))
            throw new IllegalArgumentException("hash deve contenere almeno un carattere");

        return hashStrings.add(hash);
    }

    /*
     *   OVERVIEW: Rimuove un hash dalla lista
     *   REQUIRES: hash != null, hash != ""
     *   MODIFIES: this
     *   EFFECTS: Rimuove un hash dalla lista hashStrings
     *   THROWS:
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public boolean removeElementHash(String hash) {
        if(hash == null)
            throw new NullPointerException();

        if(hash.equals(""))
            throw new IllegalArgumentException("hash deve contenere almeno un carattere");

        return hashStrings.remove(hash);
    }

    /*
     *   OVERVIEW: Controlla se un hash è presente nella lista
     *   REQUIRES: hash != null, hash != ""
     *   MODIFIES:
     *   EFFECTS: Ritorna true se l'hash cercato è presente nella lista hashStrings, altrimenti false se non è presente
     *   THROWS:
     *      IllegalArgumentException, quando owner e password non contengono almeno un carattere (Unchecked)
     */
    public boolean elementExist(String hash) {
        if(hash == null)
            throw new NullPointerException();

        if(hash.equals(""))
            throw new IllegalArgumentException("hash deve contenere almeno un carattere");

        return hashStrings.contains(hash);
    }

    /*
     *   OVERVIEW: Ritorna una copia della lista degli hash
     *   REQUIRES:
     *   MODIFIES:
     *   EFFECTS: Ritorna una copia della lista hashStrings
     *   THROWS:
     */
    public List<String> getAllElementsHash() {
        return new ArrayList<>(hashStrings);
    }
}
