# PairVault 2 – Archiv für Name und Passwort

Eine minimalistische, eigenständige Website für GitHub Pages. Keine Registrierung, kein Backend, keine externen Bibliotheken.

## Funktionen

- **Eintragen:** Name (gleich Benutzername, maximal 29 Zeichen) und Passwort eingeben oder mit den Schaltflächen rechts aus der Zwischenablage einsetzen.
- **Speichern:** Das Paar wird verschlüsselt im lokalen Gerätearchiv gespeichert. Beide Eingabefelder werden geleert.
- **Archiv:** Jeder Name ist ein eigener aufklappbarer Ordner. **Alle Ordner sind beim Öffnen standardmäßig geschlossen.**
- **Suchen:** Ins Suchfeld im Archiv tippen. Die Liste wird gefiltert und passende Namen werden als **anklickbare Vorschläge** eingeblendet. Bei der Auswahl öffnet sich der gewählte Eintrag.
- **Kopieren:** Benutzername und Passwort lassen sich separat über die rechts angeordneten Schaltflächen kopieren.
- **Verwalten:** Passwort anzeigen/verbergen, Einträge bearbeiten oder löschen.
- **Fester Bildschirm:** Keine Seitenbewegung, kein automatischer Eingabe-Zoom oder Gestenzoom in der Web-App-Darstellung. Nur längere Listen scrollen intern. Browser oder Betriebssystem können eigene Bedienungshilfen zum Vergrößern anbieten.

## Start und Speicherung – wichtig!

**Neue Installation:** PairVault öffnet sich sofort. Das früher verwirrende Einrichten eines Master-Passworts entfällt. Die App erzeugt automatisch einen **nicht exportierbaren AES-256-GCM-Geräteschlüssel**, den sie in IndexedDB des Browsers speichert. Die Einträge liegen damit **verschlüsselt** im lokalen Browser-Speicher (localStorage).

**Bestehende PairVault-Archive aus Version 1:** Das frühere Archiv wurde mit einem Master-Passwort verschlüsselt. Falls so ein Archiv im selben Browser vorhanden ist, fragt die neue App **ein einziges Mal** nach dem bisherigen Master-Passwort, damit die bestehenden Daten übernommen werden können. Danach startet sie ohne Passwortabfrage. Die Originaldaten werden nur nach erfolgreicher Übernahme ersetzt. **Wichtig: Für die Übernahme nicht die Browserdaten löschen!**

**Sicherheitsunterschied:** Ohne Master-Passwort ist das Archiv bequemer, aber weniger geschützt vor anderen Personen, die Zugang zu deinem entsperrten Gerät oder Browserprofil haben. Ein gespeicherter Geräteschlüssel ist **kein vollwertiger Ersatz für ein Passwortmanager-Master-Passwort**. Nutze PairVault nur auf einem privaten, gesicherten Gerät und nicht für besonders kritische Zugangsdaten.

Die App versendet deine Einträge nicht an einen eigenen Server. Cookies, Zwischenablage, Browsererweiterungen und kompromittierte Geräte können trotzdem Sicherheitsrisiken darstellen.

## Backups

- Im Archiv auf **„Backup speichern“** klicken und ein **eigenes Backup-Passwort mit mindestens 10 Zeichen** eingeben. Die Sicherung wird mit PBKDF2-SHA-256 (250.000 Iterationen) und AES-256-GCM verschlüsselt und als JSON-Datei heruntergeladen.
- Über **„Backup laden“** die JSON-Datei auswählen und das Backup-Passwort eingeben. Ältere Backups werden ebenfalls unterstützt; dafür braucht man das damalige Master-Passwort.
- **Regelmäßig Backups speichern!** Bei Verlust von Browserdaten, des automatisch erzeugten Geräteschlüssels oder beim Gerätewechsel sind lokal gespeicherte Einträge ohne ein solches Backup nicht wiederherstellbar. Verliere das Backup-Passwort nicht.
- Speichere niemals unverschlüsselte Passwortlisten oder Backups mit Zugangsdaten in einem öffentlichen GitHub-Repository.

## Auf GitHub Pages veröffentlichen

1. GitHub-Repository `pairvault` verwenden oder neu erstellen.
2. Alle **entpackten App-Dateien** (HTML, CSS, JS, Icons, Manifest) ins Repository hochladen und vorhandene Dateien ersetzen. **Keine echten Zugangsdaten hochladen.**
3. Unter **Settings → Pages** die Einstellung **Deploy from a branch → main → /(root)** aktivieren.
4. Unter `https://DEINNAME.github.io/pairvault/` aufrufen. Auf dem iPhone über Safari **Teilen → Zum Home-Bildschirm** eine App-Verknüpfung mit dem eigenen Icon anlegen.

**Bestehende Installation:** Vor jedem Update eine verschlüsselte Sicherung exportieren. Für die automatische Übernahme muss dieselbe Website-Adresse (Origin) und dasselbe Browserprofil weiterverwendet werden.

## Dateien

```text
pairvault/
├── index.html
├── styles.css
├── app.js
├── manifest.webmanifest
├── favicon.svg
├── icon-192.png
├── icon-512.png
├── apple-touch-icon.png
└── README.md
```

Die Website benötigt HTTPS für WebCrypto. GitHub Pages bietet HTTPS an. Bei Safari kann der Einfügen-Button den manuellen Weg **Eingabefeld lange drücken → Einsetzen** benötigen.
