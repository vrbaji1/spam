# Detekce a blokace rozesílání nevyžádané pošty

Detekce a blokace rozesílání nevyžádané pošty se provádí přímo na hlavních routerech v jednotlivých oblastech.

## kontrola_spam.py
Tento skript má za úkol kontrolovat stav blokace na těchto routerech, o vzniklé nebo ukončené blokaci informovat zákazníky, a evidovat informace v databázi.

```
Použití:
kontrola_spam.py [-h|--help]
```

## Spouštění plánovačem

Kontrola blokace rozesílání nevyžádané pošty stačí spouštět jednou za půl hodiny:

```
*/30 *  * * *   non-root-user /opt/detekce_utoky/kontrola_spam.py
```
