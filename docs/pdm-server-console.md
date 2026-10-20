# SolidCraft PDM — console server locale

Applicazione nativa separata dal CAD, per valutazione locale. Il processo della console avvia e arresta soltanto il proprio server HTTPS su `127.0.0.1`. La chiusura della console arresta quel server.

1. Aprire la console. In **Setup**, scegliere una cartella privata già posseduta dal proprio account Windows e una **nuova** sottocartella per l'installazione fisica del server. Questa cartella è distinta dalle aree di lavoro dei client.
2. Indicare l'ID dell'amministratore iniziale e la porta locale (`0` sceglie una porta libera per una nuova installazione). Premere **Create NEW archive and start**.
3. In **Status**, controllare identità server, amministratore autenticato, endpoint e backend `redb`.
4. In **Accounts**, creare utenti, modificare i ruoli, abilitare/disabilitare account o sostituire una credenziale. Disabilitazione e reset richiedono conferma. Le autorizzazioni effettive sono restituite dal server; il nome di un account non gli assegna privilegi.
5. In **Audit**, caricare le transizioni riuscite, con paginazione. Non è un registro degli accessi negati né un registro a prova di manomissione.
6. Arrestare il server prima di usare **Backup / Restore**. Un backup richiede una nuova cartella. Il ripristino richiede una nuova installazione e un backup della stessa identità del server selezionato; conserva l'installazione originale.

Per riaprire un server, scegliere la sua cartella di installazione con **Open existing console installation**, quindi avviarlo da **Status**. Sono necessari i metadati originali della console, il certificato e la chiave TLS originali e la credenziale dell'amministratore nel gestore credenziali nativo del medesimo account Windows. Un percorso esistente arbitrario non viene inizializzato né migrato. Le installazioni incomplete vengono conservate e segnalate.

Le nuove credenziali sono casuali e catturate nel gestore credenziali nativo prima di pubblicare l'autorità. Non sono mostrate dalla console, scritte nei log o memorizzate in chiaro nei file di configurazione. La creazione di un account cattura la credenziale **localmente**: il trasferimento sicuro e l'abilitazione all'accesso da un altro computer richiedono un futuro flusso di enrollment.

Se una modifica account perde la risposta di rete, la console conserva un'intenzione privata con lo stesso ID richiesta e il relativo verificatore, senza bearer. Le nuove modifiche restano bloccate: **Retry exact pending request** ripete precisamente la richiesta originaria, anche dopo il riavvio, e completa la pubblicazione della credenziale locale solo dopo la risposta idempotente del server. Un errore di autenticazione o una mancata verifica cancella l'indicazione di autorità verificata; il server posseduto resta arrestabile da **Status**.

Se una ricevuta storica viene superata da una revisione amministrativa successiva, il retry segnala esplicitamente il caso e conserva la credenziale locale esistente: una vecchia ricevuta non deve sovrascrivere una credenziale più recente. Un rifiuto di autenticazione/autorizzazione durante il retry conserva l'intenzione pendente, perché da solo non dimostra che la richiesta originale non fosse già stata eseguita.

La nuova cartella viene creata privata prima dei file TLS: su Windows il codice usa gli strumenti di sistema `whoami` e `icacls` per rimuovere l'ereditarietà e concedere accesso all'account corrente e SYSTEM, verificando l'esito. Su Unix usa permessi 0700. Le cartelle esistenti e i loro antenati non ricevono modifiche alle ACL.

Il backup dell'archivio contiene metadati privati e deve essere protetto. Non include le chiavi TLS o il contenuto del gestore credenziali del sistema operativo: conservare anche l'installazione originale e il relativo account Windows per il recupero. Non avviare contemporaneamente l'originale e la copia ripristinata.

Sono fuori dallo scopo consegnato: LAN, relay/cloud, installazione come servizio di sistema, firma degli eseguibili ed enrollment remoto degli account.

## Verifica riproducibile

`solidcraft-pdm-admin --headless-proof NEW_ABSOLUTE_ROOT` crea un nuovo archivio giocattolo, effettua realmente le chiamate TLS/capabilities/admin con uno store credenziali esclusivamente in memoria e usa la stessa funzione di disegno dei widget della console. La finestra eframe resta nascosta; un framebuffer WGPU separato cattura i widget, poiché eframe omette il normale rendering delle finestre nascoste. Il codice conserva i delta delle texture fin dal primo frame e stabilizza il layout prima della cattura. Richiede un percorso assoluto inesistente con genitore esistente. La schermata prodotta è `NEW_ABSOLUTE_ROOT/server-console-proof.png`; il server viene arrestato all'uscita. I dati di questa prova non costituiscono un'installazione riutilizzabile: la credenziale in memoria termina col processo.

Compilazione e prove effettive sono documentate in server-console-verification.md.

Una sola invocazione della prova cattura tre pagine reali nella nuova cartella: `server-console-proof.png` (Status), `server-console-accounts.png` (Accounts) e `server-console-audit.png` (Audit). Le pagine condividono lo stesso contesto egui e lo stesso renderer GPU, conservando l'atlante delle texture e stabilizzando ogni pagina prima della cattura.

La prova conserva la tessellazione di ciascun fotogramma insieme ai relativi delta delle texture, cosi la crescita successiva dei caratteri non altera le schermate precedenti.
