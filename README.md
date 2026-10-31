# PairVault 3 – ohne Archiv-Passwort

**Diese Version fragt NIE nach einem Entsperr-, Master- oder Backup-Passwort.**

## So funktioniert es

- Direkt auf **Eintragen** öffnen: Name (= Benutzername, maximal 29 Zeichen) und Passwort eingeben oder über **Einsetzen** aus der Zwischenablage übernehmen.
- **Im Archiv speichern** leert beide Felder.
- Über **Archiv** auf geschlossene Account-Ordner zugreifen, durch Antippen öffnen, beide Werte separat kopieren, anzeigen, bearbeiten oder löschen.
- Die Suche filtert nach Namen und schlägt passende Accounts vor.
- Die App hat eine feste Smartphone-Ansicht ohne Seiten-Scrollen; lange Listen scrollen nur innerhalb des Archivs. Eingabefelder haben mindestens 16px gegen Safari-Eingabezoom.
- **Backup speichern** erstellt eine lesbare JSON-Datei **ohne Passwort**; **Backup laden** stellt diese wieder her. Die App warnt vor dem Download, dass dieses Backup **unverschlüsselt** ist.

## Speicherung, Datenübernahme und Sicherheit

Lokal gespeicherte Daten aus **PairVault v2** bleiben mit dem automatisch im Browser gespeicherten Geräteschlüssel nutzbar, sofern dieselbe GitHub-Pages-Adresse und dasselbe Browserprofil verwendet werden. Die App fragt **kein Passwort** ab. Diese lokale AES-GCM-Geräteverschlüsselung schützt nicht vor jemandem, der deinen bereits entsperrten Browser verwenden kann.

**Wichtig bei Daten aus PairVault v1:** Alte Archive waren mit einem persönlichen Master-Passwort verschlüsselt. Ohne dieses alte Passwort ist eine Entschlüsselung mathematisch nicht möglich. PairVault v3 zeigt absichtlich **keine Entsperrmaske** und erstellt bei einem solchen Altbestand ein neues separates Archiv. Die alten verschlüsselten Daten bleiben im Browser erhalten und werden NICHT gelöscht. Wenn du sie retten musst, brauchst du die alte App und das alte Passwort. **Vor dem Update vorsorglich ein Backup in der alten App erstellen, soweit möglich.**

**Backups enthalten Passwörter im Klartext.** Teile sie nicht, speichere sie nicht in einem öffentlichen GitHub-Repository und bewahre sie nur an einem geschützten Ort auf. Beim Löschen der Browserdaten kann der lokale Geräteschlüssel verloren gehen.

## Installation auf GitHub Pages

1. Die ZIP entpacken und die enthaltenen Dateien in das bestehende Repository `pairvault` hochladen (Dateien ersetzen).
2. In **Settings → Pages** GitHub Pages über `main` und `/(root)` aktivieren.
3. Seite über die bekannte GitHub-Pages-Adresse öffnen und gegebenenfalls Safari aktualisieren.
4. Auf dem iPhone optional über Safari **Teilen → Zum Home-Bildschirm** als App hinzufügen.

**Nicht ins GitHub-Repository hochladen:** echte Zugangsdaten, JSON-Backups oder lokale Browserdaten.

## Dateien

- `index.html`: Oberfläche und zwei Reiter
- `app.js`: Eintragen, Suche, Kopieren, lokale Geräteverschlüsselung, passwortfreie Backups
- `styles.css`: feste mobile Darstellung
- App-Icons, Manifest und diese Anleitung
