# PairVault – verschlüsseltes Namen-und-Passwort-Archiv

Eine kostenlose, eigenständige App für GitHub Pages. Keine Registrierung, kein Server, keine externen Bibliotheken.

## Funktionen

1. **Eintragen:** Name (maximal 29 Zeichen, gilt gleichzeitig als Benutzername) und Passwort in zwei Felder eingeben. **Einsetzen** rechts daneben liest die Text-Zwischenablage, soweit der Browser es erlaubt.
2. **Speichern:** Das Paar wird in deinem lokalen, verschlüsselten Archiv gespeichert. Beide Eingabefelder werden anschließend geleert.
3. **Archiv:** Über den zweiten Reiter öffnest du die Ordnerübersicht. Jeder Name hat einen aufklappbaren Ordner mit **Benutzername** und **Passwort** und jeweils einem eigenen Kopierbutton am rechten Rand.
4. Passwörter sind zunächst verborgen, können einzeln eingeblendet und bei Bedarf geändert oder gelöscht werden.
5. Du kannst nach Namen suchen und ein **verschlüsseltes Backup exportieren/importieren**.
6. Die App bleibt im festen Bildschirm-Layout: ohne Bildlauf der Seite, ohne Fokus-Zoom bei Eingaben. Die Archiv-Liste kann bei vielen Namen innerhalb der Seite scrollen.

## Wichtig zur Speicherung

- Bei der ersten Verwendung erstellst du ein **Master-Passwort** (mindestens 10 Zeichen). Bei weiteren Aufrufen entsperrst du damit dein Archiv.
- Zugangsdaten werden **lokal im jeweiligen Browser** mit **AES-256-GCM** verschlüsselt gespeichert. Der Schlüssel wird mittels **PBKDF2-SHA-256 mit 250.000 Iterationen** aus dem Master-Passwort abgeleitet.
- Die App sendet Namen oder Passwörter **nicht an einen Server**. Es gibt keine Cloud-Synchronisierung.
- Browserdaten löschen, im privaten Modus arbeiten oder das Gerät wechseln kann ohne Backup zum Verlust der gespeicherten Daten führen.
- **Unbedingt ein Backup speichern!** Im Archiv unten auf **„Backup speichern“** tippen. Das Backup ist weiterhin verschlüsselt und braucht zum Öffnen dein Master-Passwort. **Ohne Master-Passwort ist keine Wiederherstellung möglich.**
- Auf fremden oder nicht vertrauenswürdigen Geräten nicht verwenden. Auch lokale Verschlüsselung kann ein kompromittiertes Gerät oder bösartige Browsererweiterungen nicht zuverlässig schützen.
- Auf iOS/Safari ist der Button **Einsetzen** nach Möglichkeit direkt nutzbar; wenn Safari den Zwischenablage-Zugriff ablehnt, das Eingabefeld lange drücken und **„Einsetzen“** aus dem iOS-Menü wählen.
- Einträge mit identischem Namen werden nicht versehentlich überschrieben. Vorhandene Namen können im Archiv bearbeitet werden.

## Auf GitHub Pages bereitstellen

1. Auf https://github.com/new ein öffentliches Repository, z. B. `pairvault`, erstellen.
2. **Nur die App-Dateien** aus diesem Ordner hochladen (keine echten Passwörter, keine unverschlüsselten Exporte).
3. Unter **Settings → Pages → Build and deployment** die Option **Deploy from a branch** wählen, Branch `main`, Ordner `/(root)` und **Save**.
4. Die Website wird unter `https://DEINNAME.github.io/pairvault/` verfügbar.
5. Über Safari kannst du die Website mit **Teilen → Zum Home-Bildschirm** als App ablegen. Das App-Icon zeigt einen goldenen Ordner mit Schloss auf dunkelblauem Hintergrund.

## Projektdateien

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

**Hinweis:** HTTPS ist für den sicheren Zwischenablagezugriff und WebCrypto erforderlich. GitHub Pages stellt HTTPS bereit.
