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
        f(sdc)= <credentials,storage> -->
        <{(String,SecurePassword)0,...,(String,SecurePassword)n},{SecureDataInfo0,...,SecureDataInfoK}> -->
        dove SecureDataInfo è composto dal dato cifrato e dalla lista di utenti autorizzati. n == credentials.size()-1 && K == storage.size()-1

Invariante di rappresentazione:
    credentials != null, storage != null && 
    forall(k,y appartenente a credentials.getAllKeys()).(k != null && k != y) => (credentials.get(k) != null)
    forall(e appartenente a storage.getAllElements()) => (e != null && forall(owner appartenente a e.getAllOwners()) => (owner appartiene a credentials.getAllKeys()))
*/

public class SecureDataCollection<E> implements SecureDataContainer<E> {
    //Tabella hash contente le credenziali degli utenti registrati
    private HashMap<String, SecurePassword> credentials = new HashMap<>();

    //Lista contenente tutti i dati degli utenti
    private List<SecureDataInfo<E>> storage = new ArrayList<>();

    /*
    *   OVERVIEW: Crea l’identità di un nuovo utente della collezione
    */
    @Override
    public void createUser(String id, String passw) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, UsernameNotAvailableException {

        if(id == null || passw == null)
            throw new NullPointerException();

        if(id.equals("") || passw.equals(""))
            throw new IllegalArgumentException("id e passw devono contenere almeno un carattere");

        //Cifra la password
        SecurePassword encrypted_password = new SecurePassword(passw);

        //Aggiunge l'utente se non esiste
        if(credentials.putIfAbsent(id, encrypted_password) != null)
            throw new UsernameNotAvailableException("Utente già registrato");
    }

    /*
     *   OVERVIEW: Restituisce il numero degli elementi di un utente presenti nella collezione
     */
    @Override
    public int getSize(String owner, String passw) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAuthenticationException {
        if(owner == null || passw == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            int size = 0;
            for(SecureDataInfo<E> data : storage) {
                //Controlla se l'elemento appartiene all'utente
                if(data.getOwners().contains(owner))
                    size++;
            }
            return size;
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Inserisce il valore del dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public boolean put(String owner, String passw, E data) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidAuthenticationException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            SecureDataInfo<E> element = new SecureDataInfo<>(owner, data, passw);
            return storage.add(element);
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Ottiene una copia del valore del dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public E get(String owner, String passw, E data) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, NoSuchElementException, InvalidAuthenticationException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            SecureDataInfo<E> element_to_search = new SecureDataInfo<>(owner, data);
            for(SecureDataInfo<E> element : storage) {
                //Controlla se l'elemento appartiene all'utente (La ricerca avviene per confronto tra hash)
                if(Arrays.equals(element.getHash(), element_to_search.getHash()) && element.getOwners().contains(owner))
                    return element.getValue(passw);
            }
            throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Rimuove il dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public E remove(String owner, String passw, E data) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, NoSuchElementException, InvalidAuthenticationException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            SecureDataInfo<E> element_to_search = new SecureDataInfo<>(owner, data);
            for(SecureDataInfo<E> element : storage) {
                //Controlla se l'elemento appartiene all'utente (La ricerca avviene per confronto tra hash)
                if(Arrays.equals(element.getHash(), element_to_search.getHash()) && element.getOwners().contains(owner))
                {
                    if(storage.remove(element))
                        return element.getValue(passw);
                    else
                        throw new NoSuchElementException("Il dato non è presente nella collezione");
                }
            }
            return null;
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Crea una copia del dato nella collezione se vengono rispettati i controlli di identità
     */
    @Override
    public void copy(String owner, String passw, E data) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchElementException, InvalidAuthenticationException {
        if(owner == null || passw == null || data == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            boolean found = false;
            SecureDataInfo<E> element_to_search = new SecureDataInfo<>(owner, data);
            for(SecureDataInfo<E> element : storage) {
                //Controlla se l'elemento appartiene all'utente (La ricerca avviene per confronto tra hash)
                if(Arrays.equals(element.getHash(), element_to_search.getHash()) && element.getOwners().contains(owner))
                {
                    SecureDataInfo<E> newElement;
                    //Se il dato è cifrato crea una copia mantenendo la cifratura, altrimenti crea una copia non cifrata
                    if(element.isEncrypted())
                        newElement = new SecureDataInfo<>(owner, data, passw);
                    else
                        newElement = new SecureDataInfo<>(owner, data);

                    storage.add(newElement);
                    found = true;
                    break;
                }
            }

            if(!found)
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Condivide il dato nella collezione con un altro utente se vengono rispettati i controlli di identità
     */
    @Override
    public void share(String owner, String passw, String other, E data) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, NoSuchElementException, InvalidAuthenticationException, UsernameNotAvailableException {
        if(owner == null || passw == null || other == null || data == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            //Controllo se l'utente con cui condividere il dato esiste
            if(!credentials.containsKey(other))
                throw new UsernameNotAvailableException("L'utente " + other + " non esiste");
            else if(owner.equals(other))
                throw new UsernameNotAvailableException("L'utente non può condividere un dato con se stesso");

            boolean found = false;
            SecureDataInfo<E> element_to_search = new SecureDataInfo<>(owner, data);
            for(int i = 0; i < storage.size(); i++) {
                //Controlla se l'elemento appartiene all'utente (La ricerca avviene per confronto tra hash)
                if(Arrays.equals(storage.get(i).getHash(), element_to_search.getHash()) && storage.get(i).getOwners().contains(owner))
                {
                    //Decifra il dato in modo irreversibile
                    // (La cifratura del dato è disponibile solo se privato, condividendolo diventa pubblico)
                    storage.get(i).makePublic(passw);
                    //Aggiunge l'utente alla lista di owner di un certo elemento
                    storage.get(i).addOwner(other);

                    found = true;
                    break;
                }
            }

            if(!found)
                throw new NoSuchElementException("Il dato non è presente nella collezione");
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Restituisce un iteratore (senza remove) che genera tutti i dati dell'utente in ordine arbitrario se vengono rispettati i controlli di identità
     */
    @Override
    public Iterator getIterator(String owner, String passw) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalArgumentException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException, InvalidAuthenticationException {
        if(owner == null || passw == null)
            throw new NullPointerException();

        if(authenticate_user(owner, passw))
        {
            List<E> iter_list = new ArrayList<>();
            for(SecureDataInfo<E> element : storage) {
                //Controlla se l'elemento appartiene all'utente (La ricerca avviene per confronto tra hash)
                if(element.getOwners().contains(owner))
                    iter_list.add(element.getValue(passw));
            }

            return Collections.unmodifiableList(iter_list).iterator();
        }
        else
            throw new InvalidAuthenticationException("Autenticazione fallita");
    }

    /*
     *   OVERVIEW: Autentica l'utente tramite id(username) e password
     */
    private boolean authenticate_user(String id, String passw) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalArgumentException {
        if(id == null || passw == null)
            throw new NullPointerException();

        SecurePassword encrypted_password = credentials.get(id);
        if(encrypted_password != null && encrypted_password.verify_password(passw))
            return true;
        else
            return false;
    }
}
