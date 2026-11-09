# log-scan

Skript stáhne seznam blokovaných adres **Unified hosts + fakenews** od StevenBlack,
uloží ho do cache a prohledá s ním logy. Na konci vypíše, **které adresy ze seznamu
StevenBlack** se v lozích objevily a v kterých souborech.

Poslední úprava: 2026-11-09 (verze 12)

---

## Rychlý start

```
python hosts_log_scan.py "C:\cesta\k\logum"
```

Cesta k logům je jediný povinný parametr (v zadání označený ADR). Složka se prochází
včetně podsložek, soubory `.gz` se čtou přímo.

Výstup (příklad):

```
#TOP 10 nalezených adres ze seznamu StevenBlack (počet výskytů)
  1.        3x  4u.pl;
  2.        2x  google.com;
#TOP 10 log souborů (počet zásahů / unikátních domén)
  1.        5x     2 unik.  dns.log;
```

### Jak se hledá a co se vypisuje

1. **Filtrování** probíhá podle **přesných záznamů** ze seznamu StevenBlack. Když je v logu
   `www.google.com`, ale v seznamu je jen `analytics.google.com`, počítá se jen ten
   druhý. Běžný provoz se nepočítá.
2. **Výpis** je ve výchozím stavu zkrácen na konec adresy (second-level + TLD):
   `stat.4u.pl` a `adstat.4u.pl` se sečtou jako `4u.pl`. Zkrátí se až nalezené záznamy,
   ne celý log.

Chceš-li ve výpisu vidět celé adresy ze seznamu (`stat.4u.pl`, `analytics.google.com`),
spusť skript s přepínačem `--no-sld-tld`:

```
python hosts_log_scan.py "C:\cesta\k\logum" --no-sld-tld
```
```
#TOP 10 nalezených adres ze seznamu StevenBlack (počet výskytů)
  1.        2x  stat.4u.pl;
  2.        2x  analytics.google.com;
  3.        1x  adstat.4u.pl;
```

## Přepínače

| Přepínač | Co dělá |
|---|---|
| `adr` | adresář s logy (povinný, pokud nepoužiješ `--repo`) |
| `--top N` | počet řádků ve statistice (výchozí 10) |
| `--sld-tld` / `--no-sld-tld` | zkrácený výpis (`stat.4u.pl` -> `4u.pl`). **Výchozí je zapnuto**, vypnutí `--no-sld-tld` |
| `--subdomains` | `x.ads.example.com` v logu se spáruje se záznamem `ads.example.com` ze seznamu |
| `--refresh` | ignorovat ETag a stáhnout seznam znovu |
| `--offline` | nekontaktovat server, použít cache |
| `--cache-dir` | kde je cache (výchozí složka `.cache/hosts_log_scan` vedle skriptu) |
| `--workers N` | počet procesů pro velké logy (výchozí podle jader, nejvýš 8; strop platí jen pro výchozí hodnotu) |
| `--part-mb N` | největší velikost úseku souboru v MB (výchozí 32); velké logy se dělí na úseky, které se zpracují paralelně |
| `--repo URL` | logy stáhnout z git repozitáře a udržovat je aktuální |
| `--subdir`, `--logs-dir`, `--sync-days`, `--sync-now` | doplňky k `--repo` |
| `--report-dir` | kam ukládat reporty (výchozí `reports/`) |

---

## Jak funguje paralelní zpracování

Cílem je, aby žádný proces nečekal, dokud je kde pracovat. I **jeden velký log** se proto
rozdělí na úseky a procesy si je rozeberou.

1. **Úkol = úsek souboru.** Log se rozdělí podle **bajtových pozic** na stejně velké
   úseky (výchozí 32 MB, přepínač `--part-mb`). Soubor 5 GB tak dá asi 160 úkolů,
   malý soubor zůstane jedním úkolem.
2. **Dynamické přidělování.** Úkoly leží ve společné frontě. Proces, který dokončí úkol,
   si hned vezme další. Když dva logy po 300 MB skončí dřív, jejich procesy se pustí
   do zbytku obřího logu a nečekají.
3. **Největší úkoly první.** Aby na konci nezbyl jeden dlouhý úkol sám.
4. **Sečtení výsledků.** Každý úsek vrátí počty nalezených adres. Počty částí jednoho
   souboru se na konci sečtou, takže výsledek je stejný jako při zpracování celého souboru.
5. **Velikost úseku se přizpůsobuje.** Je nejvýš `--part-mb`, ale menší, když je logů
   málo, aby se práce rozdělila na dost úkolů (zhruba 4 na proces). Nejmenší úsek je
   4 MB, protože menší by se kvůli režii nevyplatily.

**Jak se řeže, aby se nic neztratilo ani nezdvojilo.** Hranice úseku může padnout
doprostřed řádku, ba i doprostřed slova:

- úsek, který nezačíná na začátku souboru, **zahodí první (rozříznutý) řádek**, protože
  patří úseku před ním,
- řádek, který **přesahuje** hranici, dočte do konce. Patří úseku, ve kterém začíná.

Zalomení řádku je v UTF-8 jediný bajt a nikdy se nevyskytne uvnitř jiného znaku,
takže řez nerozbije ani diakritiku. Každý řádek tak zpracuje přesně jeden úsek.

**Úkol vs. blok.** Úsek (úkol) dostane jeden proces. Uvnitř úkolu se čte po **blocích** po
4 MB (`READ_CHUNK`), aby nebyl v paměti celý úsek najednou. Bloky tedy hlídají paměť,
úseky rozdělují práci.

**Kdy se paralelně nejede.** Pod 20 MB logů dohromady (rozjezd procesů by stál víc, než
ušetří), při `--workers 1` a u souborů `.gz`. Komprimovaný soubor se musí číst od
začátku a nedá se do něj skočit doprostřed, takže jeden `.gz` zpracuje vždy jeden proces.

---

## Co je ETag a jak ho skript používá

**ETag** (entity tag) je „otisk verze“ souboru, který posílá webový server spolu s
odpovědí. Server ho vytvoří sám. Má tvar řetězce v uvozovkách, třeba
`"1f01476bbbc8…"`. Když se soubor změní, ETag se změní. Když zůstane stejný, ETag
zůstane také.

Proč je užitečný: bez něj by skript musel při každém spuštění stáhnout celý hosts
soubor (asi 2,4 MB), aby zjistil, jestli je nový. S ETagem se jen zeptá:

1. Poprvé: skript stáhne soubor a server pošle ETag. Skript si ho uloží do
   `hosts_unified_fakenews.meta.json`.
2. Příště: skript pošle serveru dotaz „mám verzi s tímto ETagem, změnilo se něco?“
   (hlavička `If-None-Match`).
3. Server odpoví jedním ze dvou způsobů:
   - **304 Not Modified**: beze změny. Neposílá se žádný obsah, odpověď má pár stovek
     bajtů. Skript použije cache.
   - **200 OK** s novým souborem a novým ETagem: seznam se změnil, skript ho uloží.

Skript se o význam ETagu nestará, jen ho porovná. Důležité je, že ETag řeší otázku
„změnilo se to na serveru?“ rychle a bez stahování.

### Proč je tu i SHA-256

ETag říká jen, jak je to na serveru. Nic neříká o tom, **co máš uložené u sebe**.
Proto skript ukládá i otisk **SHA-256** vypočítaný z obsahu souboru v cache:

- při každém spuštění se otisk souboru v cache porovná s uloženým. Když nesedí (někdo
  soubor upravil, poškodil se disk, přerušilo se stahování), cache se zahodí a
  stáhne se znovu,
- po stažení se porovná otisk nového obsahu s uloženým. Když je stejný, cache se
  nepřepisuje.

Shrnutí: **ETag = je to na serveru jiné?**, **SHA-256 = je to u mě v pořádku a je to jiné?**

Při chybě sítě skript použije existující platnou cache a napíše varování.

---

## Historie změn

### Verze 12: rychlejší hledání v jednom procesu
- **Proč:** paralelismus zkrátil čas u víc souborů, ale pořád zbývala většina práce,
  kterou udělá každý proces. Změřil jsem, kde se v jednom procesu tráví čas na 22 MB logu:
  rozdělení na slova regulárním výrazem (0,22 s) a počítání slov (0,12 s) bylo víc než
  všechno ostatní dohromady.
- **Co se změnilo:**
  - Log se už **nedekóduje** na text. Zpracovává se přímo jako bajty: jedním průchodem
    (`bytes.translate`) se velká písmena změní na malá a vše, co nepatří do domény, na
    mezeru, a pak se text rozdělí (`bytes.split`). Obojí běží v C, bez regulárního výrazu.
    Doménová jména jsou ASCII, takže dekódování není potřeba.
  - Seznam domén a IP se pro porovnání ukládá taky jako bajty (každý proces si ho při
    startu převede). Nalezené adresy se zpět na text převádějí až na konci a jen ty,
    které se opravdu našly.
  - Regulární výraz `TOKEN_RE` a import `re` odpadly.
  - Blok čtení (`READ_CHUNK`) je 4 MB místo 8 MB. Rychlost je stejná (rozdíl v měření
    byl v rámci šumu), ale každý proces má asi o polovinu menší paměťovou špičku.
- **Výsledek (jeden proces, naměřeno):**

  | log | předchozí | nová verze | zrychlení |
  |---|---|---|---|
  | 1 soubor 22 MB | 0,42 s | 0,27 s | 1,6× |
  | 8 souborů 181 MB | 3,66 s | 2,21 s | 1,7× |
  | 8 souborů, `--subdomains` | 3,83 s | 2,44 s | 1,6× |

  Zrychlení se násobí s paralelním zpracováním (verze 11), protože každý proces je
  rychlejší. Výsledky hledání jsou shodné s předchozími verzemi (ověřeno na jednom
  souboru i osmi, se `--subdomains` i bez) a hranice úseků prošly 504 kontrolami
  (diakritika, CRLF, bez koncového zalomení, prázdné řádky).
- **Co se nezměnilo a proč:** celkový čas navíc zůstává u každého spuštění, který hledání
  nezkrátí: dotaz na server s ETagem (desítky až stovky ms podle připojení; `--offline`
  ho přeskočí), načtení seznamu (asi 80 ms) a start procesů (na Windows stovky ms).
  Na velkých logách (stovky MB a víc) jsou tyhle položky proti hledání malé.

### Verze 11: paralelní zpracování i uvnitř jednoho logu
- **Proč:** skript byl při velkých logech pomalý. Soubor byl nejmenší jednotkou práce,
  takže se dvěma logy po 300 MB a jedním 5 GB dělal největší log jediný proces a
  ostatní po krátké práci čekaly.
- **Co se změnilo:**
  - Velké logy se dělí na úseky podle bajtových pozic (výchozí 32 MB) a procesy si je
    berou z fronty. Kdo skončí, vezme další úsek, takže nikdo nečeká.
  - Soubor se čte binárně a hranice úseků se určují podle zalomení řádku. Žádný řádek
    se neztratí ani nespočítá dvakrát (podrobně viz „Jak funguje paralelní zpracování“).
  - Nový přepínač `--part-mb`. Velikost úseku se navíc přizpůsobuje počtu procesů.
  - Úkoly se řadí od největšího, ať na konci nezůstává jeden dlouhý.
  - Funkce `scan_one_file` byla nahrazena funkcemi `iter_blocks`, `scan_part` a `make_tasks`.
- **Nezměněno:** `.gz` soubory se dělit nedají a zpracuje je dál jeden proces.

### Verze 10: rychlost při jednom logu
- **Proč:** při jednom log souboru byla verze 9 pomalejší než dřívější verze 4. Paralelní
  zpracování a přepis hledání pomáhají hlavně u více velkých souborů. U jednoho souboru
  se projevila jejich režie.
- **Co se změnilo:**
  - **Hledání slov:** nový regulární výraz byl pomalejší (0,56 s proti 0,36 s na 22 MB).
    Vrátil jsem jednoduchý výraz a okrajové znaky (`.`, `-`, `_`) se ořezávají až u
    unikátních slov, ne u každého výskytu.
  - **Načtení hosts souboru:** funkce pro rozpoznání IP adresy (`ipaddress`) se volala
    pro každý řádek, i když to byla doména. Teď se volá jen u slov, která IP adresa být
    může. Načtení seznamu se zkrátilo z asi 620 ms na asi 80 ms při každém spuštění
    (množiny domén a IP jsou shodné, ověřeno).
- **Výsledek:** na jednom 22 MB logu je hledání zhruba stejně rychlé jako ve starší
  verzi (0,77 s proti 0,81 s) a se `--subdomains` rychlejší (0,78 s proti 1,31 s). Výsledky
  hledání jsou shodné.
- **Co v celkovém čase zůstává navíc oproti verzi 4:** při každém spuštění se skript
  zeptá serveru, jestli se seznam nezměnil (ETag, viz výše). Je to jeden malý dotaz
  na síť, takže přidá desítky až stovky milisekund podle připojení. Chceš-li ho
  přeskočit, spusť skript s `--offline`.

### Verze 9: zkrácený výpis je výchozí
- **Proč:** přepínač `--sld-tld` bylo nutné psát při každém spuštění.
- **Co se změnilo:** v kódu je `--sld-tld` definovaný přes `argparse.BooleanOptionalAction`
  s výchozí hodnotou `True`. Tím vznikla dvojice `--sld-tld` (zapnout) a `--no-sld-tld`
  (vypnout). Bez přepínače se výpis zkracuje na konec adresy.
- Starý zápis `--sld-tld` dál funguje, jen už není potřeba.
- Chceš-li výchozí chování změnit zpět, v kódu stačí v řádku s `--sld-tld` přepsat
  `default=True` na `default=False`.
- Příklady a tabulka přepínačů v README jsou aktualizované.

### Verze 8: `--sld-tld` jen zkracuje výpis, nezahlcuje ho běžným provozem
- **Proč:** ve verzi 7 se s `--sld-tld` zkracovala i každá adresa z logu. `www.google.com`
  nebo `mail.google.com` se pak počítaly jako zásah (`google.com`) a ve výpisu bylo
  tisíce zásahů z běžného provozu. Adresy ze seznamu StevenBlack nebyly vidět.
- **Co se změnilo:** hledání je vždy **přesné** (nebo se subdoménami s `--subdomains`)
  a závisí jen na záznamech ze seznamu. `--sld-tld` zkrátí až **nalezené** záznamy:
  `stat.4u.pl` a `adstat.4u.pl` se sečtou jako `4u.pl`.
- Širší hledání podle second-level domén (verze 7) bylo odstraněno. Počty zásahů jsou
  s `--sld-tld` i bez něj stejné (ověřeno na 181 MB logů), liší se jen seskupení ve výpisu.
- Skript je tím o něco jednodušší: odpadla interní proměnná pro režim hledání.

### Verze 7: výpis adres přímo ze seznamu StevenBlack
- **Proč:** v předchozí verzi se hledalo podle second-level + TLD, takže se vypisovaly
  zkrácené domény (např. `google.com`) a jedna doména se objevovala mnohokrát
  najednou. Potřeba byla vidět konkrétní adresy ze seznamu.
- **Co se změnilo:** výchozí režim hledá a vypisuje **přesné záznamy z hosts souboru**.
  Zkracování na second-level + TLD zůstalo jako volitelný přepínač `--sld-tld`.
  Přepínač `--full-domains` zanikl (je to nově výchozí chování).
- Nadpis statistiky je „nalezených adres ze seznamu StevenBlack“. Report uvádí i
  použitý režim hledání.

### Verze 6: cache kontrolovaná hashem
- **Proč:** kontrola podle stáří souboru (24 h, později 168 h) neřekla, jestli se
  seznam doopravdy změnil.
- **Co se změnilo:** vedle cache se ukládá `hosts_unified_fakenews.meta.json` s
  SHA-256 a ETagem. Skript se při každém spuštění zeptá serveru s ETagem (viz výše).
- Odstraněno: `--ttl` a časový limit cache.
- Přidáno: `--offline`, `--refresh` nově ignoruje ETag.

### Verze 5: rychlejší hledání
- Soubory se čtou po velkých blocích (8 MB), slova se rozsekají jedním voláním
  regulárního výrazu a spočítají `Counter`em. Python porovnává jen **unikátní** slova,
  ne každý výskyt zvlášť.
- Velké logy (od 20 MB, víc než jeden soubor) se zpracují paralelně (`--workers`).
- Na 181 MB testovacích logů se čas se `--subdomains` zkrátil z 13,4 s na 6,2 s.
  U přesného hledání je zrychlení malé (7,3 s na 6,7 s). Paralelní běh se mi nepodařilo
  změřit (testovací prostředí mělo jedno jádro).
- Výsledky jsou shodné s předchozí verzí (ověřeno).

### Verze 4: tvoje úpravy
- Cache složka u skriptu (`.cache/hosts_log_scan`), platnost cache 168 h.
- Upravený formát reportu (`#TOP …`, řádky končí středníkem).

### Verze 3: měření času
- Report i konec výpisu ukazují dobu hledání a dobu celého běhu.

### Verze 2: logy z gitu
- Přepínač `--repo` stáhne logy z git repozitáře (shallow clone) a obnovuje je
  nejvýš jednou za 7 dní. Report se ukládá do `reports/`. Složka `.git` se při
  prohledávání přeskakuje.

### Verze 1: základ podle zadání
- Stažení hosts souboru Unified + fakenews, cache, parametr s adresářem logů, TOP 10
  nalezených adres a TOP 10 log souborů.
- IP adresy: sinkhole adresy (`0.0.0.0`, `127.0.0.1`) se nehledají, protože by
  byly v každém logu. Hledají se jen skutečné IP, které se v seznamu objeví.

---

## Omezení

- Soubory `.gz` se nedají rozdělit na úseky, takže obří `.gz` zpracuje jeden proces.
- Zrychlení paralelním zpracováním závisí na počtu jader a rychlosti disku. Na pomalém
  disku se procesy o čtení dělí a další procesy už nepomohou.
- Hledání je textové: skript nepozná, jestli byla adresa skutečně zablokována, jen že
  se v logu vyskytla.
- Zkrácení výpisu zná jen běžné dvoupísmenné koncovky typu `co.uk`, `com.au`. Není to
  celý Public Suffix List.
- Seznam fake news webů nespravuje StevenBlack, ale autor rozšíření (Marktron).
  Co do něj patří, je věcí jeho úsudku.
