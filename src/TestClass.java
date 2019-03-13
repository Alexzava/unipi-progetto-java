/*
 *  Github: https://github.com/alexzava/unipi-progetto-java
 *
 *  License: Apache License 2.0
 *
 */
import java.util.Iterator;
import java.util.NoSuchElementException;

public class TestClass {

    //Test della prima implementazione
    public static void testPrimaImp() {
        SecureDataCollection secureDataCollection = new SecureDataCollection<>();
        try {
            //Crea gli utenti
            System.out.println(">Creazione degli utenti\n");
            secureDataCollection.createUser("bob", "123");
            secureDataCollection.createUser("alice", "abc");

            //Inserimento dei dati
            System.out.println(">Inserimento di dati\n");
            if(!secureDataCollection.put("bob", "123", "Pummarola")) {
                System.out.println("Il dato Pummarola non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("bob", "123", "Pasta")) {
                System.out.println("Il dato Pasta non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("alice", "abc", "Mozzarella")) {
                System.out.println("Il dato Mozzarella non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("alice", "abc", 91101)) {
                System.out.println("Il dato Mozzarella non è stato inserito\n");
                return;
            }
            System.out.println("Tutti i dati sono stati inseriti con successo\n");

            //Condivisione dei dati
            System.out.println(">Condivisione di un dato\n");
            secureDataCollection.share("alice", "abc", "bob", "Mozzarella");
            System.out.println("Condivisione avvenuta con successo\n");

            //Copia dei dati
            System.out.println(">Copia di un dato\n");
            secureDataCollection.copy("bob", "123", "Mozzarella");
            System.out.println("Dato copiato con successo\n");

            //Conteggio dei dati
            int aliceSize = secureDataCollection.getSize("alice", "abc");
            if(aliceSize < 0) {
                System.out.println("Errore, l'utente alice non ha elementi nella collezione\n");
                return;
            }
            System.out.println(">L'utente alice ha " + aliceSize + " elementi nella collezione\n");

            //Controlla e poi rimuove
            System.out.println(">Rimozione di un elemento\n");
            if(secureDataCollection.get("alice", "abc", 91101) != null &&  secureDataCollection.remove("alice", "abc", 91101) != null)
                System.out.println("L'elemento è stato cancellato con successo\n");
            else
                System.out.println("L'elemento da rimuovere non esiste\n");

            //Iteratore
            System.out.println(">L'utente bob ha i seguenti elementi nella collezione:");
            Iterator iter = secureDataCollection.getIterator("bob", "123");
            System.out.print("[ ");
            while(iter.hasNext()) {
                System.out.print(" " + iter.next());
            }
            System.out.print(" ]\n");
        } catch (Exception e) {
            System.out.println("Eccezione: " + e.getMessage());
        }
    }

    //Test della seconda implementazione
    public static void testSecondaImp() {
        SecureDataCollectionSecImp secureDataCollection = new SecureDataCollectionSecImp<>();
        try {
            //Crea gli utenti
            System.out.println(">Creazione degli utenti");
            secureDataCollection.createUser("bob", "123");
            secureDataCollection.createUser("alice", "abc");

            //Inserimento dei dati
            System.out.println(">Inserimento di dati\n");
            if(!secureDataCollection.put("bob", "123", "Pummarola")) {
                System.out.println("Il dato Pummarola non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("bob", "123", "Pasta")) {
                System.out.println("Il dato Pasta non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("alice", "abc", "Mozzarella")) {
                System.out.println("Il dato Mozzarella non è stato inserito\n");
                return;
            }
            if(!secureDataCollection.put("alice", "abc", 91101)) {
                System.out.println("Il dato Mozzarella non è stato inserito\n");
                return;
            }
            System.out.println("Tutti i dati sono stati inseriti con successo\n");

            //Condivisione dei dati
            System.out.println(">Condivisione di un dato\n");
            secureDataCollection.share("alice", "abc", "bob", "Mozzarella");
            System.out.println("Condivisione avvenuta con successo\n");

            //Copia dei dati
            System.out.println(">Copia di un dato\n");
            secureDataCollection.copy("bob", "123", "Mozzarella");
            System.out.println("Dato copiato con successo\n");

            //Conteggio dei dati
            int aliceSize = secureDataCollection.getSize("alice", "abc");
            if(aliceSize < 0) {
                System.out.println("Errore, l'utente alice non ha elementi nella collezione\n");
                return;
            }
            System.out.println(">L'utente alice ha " + aliceSize + " elementi nella collezione\n");

            //Controlla e poi rimuove
            System.out.println(">Rimozione di un elemento\n");
            if(secureDataCollection.get("alice", "abc", 91101) != null &&  secureDataCollection.remove("alice", "abc", 91101) != null)
                System.out.println("L'elemento è stato cancellato con successo\n");
            else
                System.out.println("L'elemento da rimuovere non esiste\n");

            //Iteratore
            System.out.println(">L'utente bob ha i seguenti elementi nella collezione:");
            Iterator iter = secureDataCollection.getIterator("bob", "123");
            System.out.print("[ ");
            while(iter.hasNext()) {
                System.out.print(" " + iter.next());
            }
            System.out.print(" ]\n");
        } catch (Exception e) {
            System.out.println("Eccezione: " + e.getMessage());
        }
    }

    //Test delle eccezioni per la prima implementazione
    public static void testExceptionPrimaImp() {
        //Creazione di un utente
        SecureDataCollection secureDataCollection = new SecureDataCollection();
        try {
            secureDataCollection.createUser("alex","123");
            secureDataCollection.createUser("zava","XII");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Creazione di un utente null
        System.out.println(">Creazione di un utente null");
        try {
            secureDataCollection.createUser(null, "123");
        } catch(NullPointerException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Creazione di un utente con id o passw vuoti
        System.out.println(">Creazione di un utente con id o passw vuoti");
        try {
            secureDataCollection.createUser("","");
        } catch(IllegalArgumentException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Crezione di un utente già registrato
        System.out.println(">Crezione di un utente già registrato");
        try {
            secureDataCollection.createUser("alex","abc");
        } catch(UsernameNotAvailableException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Inserimento di un dato
        try {
            secureDataCollection.put("alex","123","elemento1");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Inserimento di un dato nullo
        System.out.println(">Inserimento di un dato nullo");
        try {
            secureDataCollection.put("alex", "123", null);
        } catch(NullPointerException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Get di un dato non presente nella collezione
        System.out.println(">Get di un dato non presente nella collezione");
        try {
            secureDataCollection.get("alex","123",8910);
        } catch (NoSuchElementException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Get di un dato non appartenente all'utente
        System.out.println(">Get di un dato non appartenente all'utente");
        try {
            secureDataCollection.get("zava","XII","elemento1");
        } catch (NoSuchElementException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Credenziali utente errate
        System.out.println(">Credenziali utente errate");
        try {
            int size = secureDataCollection.getSize("alex","qwerty");
        } catch(InvalidAuthenticationException e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }

        //Condivisione del dato con un utente non registrato
        System.out.println(">Condivisione del dato con un utente non registrato");
        try {
            secureDataCollection.share("alex","123","pierino", "elemento1");
        } catch(UsernameNotAvailableException e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }
    }

    //Test delle eccezioni per la seconda implementazione
    public static void testExceptionSecondaImp() {
        //Creazione di un utente
        SecureDataCollectionSecImp secureDataCollection = new SecureDataCollectionSecImp();
        try {
            secureDataCollection.createUser("alex","123");
            secureDataCollection.createUser("zava","XII");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Creazione di un utente null
        System.out.println(">Creazione di un utente null");
        try {
            secureDataCollection.createUser(null, "123");
        } catch(NullPointerException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Creazione di un utente con id o passw vuoti
        System.out.println(">Creazione di un utente con id o passw vuoti");
        try {
            secureDataCollection.createUser("","");
        } catch(IllegalArgumentException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Crezione di un utente già registrato
        System.out.println(">Crezione di un utente già registrato");
        try {
            secureDataCollection.createUser("alex","abc");
        } catch(UsernameNotAvailableException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Inserimento di un dato
        try {
            secureDataCollection.put("alex","123","elemento1");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Inserimento di un dato nullo
        System.out.println(">Inserimento di un dato nullo");
        try {
            secureDataCollection.put("alex", "123", null);
        } catch(NullPointerException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Get di un dato non presente nella collezione
        System.out.println(">Get di un dato non presente nella collezione");
        try {
            secureDataCollection.get("alex","123",8910);
        } catch (NoSuchElementException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Get di un dato non appartenente all'utente
        System.out.println(">Get di un dato non appartenente all'utente");
        try {
            secureDataCollection.get("zava","XII","elemento1");
        } catch (NoSuchElementException e) {
            System.out.println(e + "\n");
        } catch(Exception e) {
            System.out.println(e + "\n");
        }

        //Credenziali utente errate
        System.out.println(">Credenziali utente errate");
        try {
            int size = secureDataCollection.getSize("alex","qwerty");
        } catch(InvalidAuthenticationException e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }

        //Copia di un dato non condiviso (già presente nella propria collezione)
        System.out.println(">Copia di un dato già presente nella propria collezione");
        try {
            secureDataCollection.copy("alex","123","elemento1");
        } catch(AlreadyInCollection e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }

        //Condivisione di un dato già condiviso
        System.out.println(">Condivisione di un dato già condiviso");
        try {
            secureDataCollection.share("alex","123","zava","elemento1");
            secureDataCollection.share("alex","123","zava","elemento1");
        } catch(AlreadySharedException e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }

        //Copia di un dato non condiviso (già presente nella propria collezione)
        System.out.println(">Copia di un dato già presente nella propria collezione");
        try {
            secureDataCollection.copy("alex","123","elemento1");
        } catch(AlreadyInCollection e) {
            System.out.println(e + "\n");
        } catch (Exception e) {
            System.out.println(e + "\n");
        }
    }
}