#!/usr/bin/python3
#coding=utf8

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 29.1.2021
Posledni uprava: 19.4.2022
"""

import sys, socket, signal, getpass, getopt, struct
sys.path.append('/opt/lib')
import dtb, mail, api

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)


TEMPLATE_BLOKACE="""Vážený zákazníku,

naše routery zaznamenaly podezřelou aktivitu pocházející z Vaší přípojky z IP adresy %s, která byla vyhodnocena jako pokus o odesílání SPAMu. Tato komunikace byla proto zablokována.

Pokud skutečně dochází k odesílání SPAMu, je nutné zbavit počítač škodlivého kódu. Nemusí se jednat jen o počítač, ale o jakékoliv zařízení připojené k Vaší vnitřní síti (např. telefon, tablet, router, kamerový systém atd.), především pokud má přidělenu veřejnou IP adresu a není řádně zabezpečeno.

Blokace nemá vliv na přijímání ani odesílání emailů přes webové rozhraní. Byla nastavena na 24h, poté bude automaticky zrušena. Pro okamžité zrušení blokace nás kontaktujte emailem nebo telefonicky. Při opětovných problémech bude blokace opět aktivována a pokud se tak bude dít opakovaně, dojte k trvalé blokaci takovéto komunikace.


Dále čtěte, pokud máte zájem o detailnější informace:
---------------------------------------------------------

Z důvodu neobvykle vysoké intenzity komunikace na TCP portech 25, 465 a 587 během posledních 30 minut byla komunikace na těchto portech zablokována. To znamená, že nebude možné odesílat emaily pomocí SMTP apod.

Pokud potřebujete zjistit, které konkrétní zařízení ve Vaší vnitřní síti za NAT problém způsobilo, můžete to zjistit sledováním komunikace na zmiňovaných TCP portech. Z naší strany toto není možné automatizovaně zjistit, neboť tyto informace má jen Váš router.

Pokud provozujete SMTP server, případně nějaký nástroj na hromadné odesílání emailů, je vhodné omezit odesílání na např. 5 vláken. Pokud od nás máte firemní připojení a potřebujete specifické nastavení, kontaktujte nás prosím emailem nebo telefonicky.

(toto je automaticky generovaný e-mail)

-- 
S pozdravem

Firma s.r.o.
Uliční 123
Město
123 45

tel: 123 456 789
e-mail: info@firma.example
web: www.firma.example"""


TEMPLATE_BLOKACE_ZRUSENA="""Vážený zákazníku,

blokace byla zrušena, odesílání emailů z IP %s je opět povoleno. Došlo k tomu buď automaticky po 24h od začátku blokace, nebo po žádosti blokaci zrušit.

(toto je automaticky generovaný e-mail)

-- 
S pozdravem

Firma s.r.o.
Uliční 123
Město
123 45

tel: 123 456 789
e-mail: info@firma.example
web: www.firma.example"""


def usage(vystup):
  vystup.write("""./kontrola_spam.py ["-h"|"--help"]

  Kontrola blokace rozesilani posty na hlavnich routerech v jednotlivych oblastech.
  Detekce rozesilani nevyzadane posty se provadi primo na techto routerech.
  \n""")


def ip2int(addr):                                                               
    return struct.unpack("!I", socket.inet_aton(addr))[0]                       


def int2ip(addr):                                                               
    return socket.inet_ntoa(struct.pack("!I", addr)) 


def getBlock(L,ip_zarizeni):
  """ Získat informace o blokovaných IP z dané oblasti.
  @param L: seznam, kam přidávat nalezené IP
  @param ip_zarizeni: IP zařízení, které řeší danou oblast
  """
  apiros = api.ApiRos(ip_zarizeni, timeout=10)
  try:
    vysl=apiros.command(["/ip/firewall/address-list/getall","?list=spam_blokace","?disabled=false"])
  except socket.timeout as err:
    sys.stderr.write("ERROR Mikrotik %s vyprsel timeout: %s! To nam znefunkcnuje celou detekci SPAMu a je nutne vyresit!\n" % (ip_zarizeni,err))
    #nema smysl pokracovat, takto by se nam vratily informace, ze uz na danem zarizeni zadne blokace nemame!
    #a info me na mail!
    mail.send(fro='user@server.firma.example', to='technik@firma.example', subject='nefunkční detekce SPAMu', text='ERROR Mikrotik %s vypršel timeout: %s! To nám znefunkčňuje celou detekci SPAMu a je nutné vyřešit!' % (ip_zarizeni,err), charset='utf8')
    sys.exit(1)

  for reply, attrs in vysl:
    if reply =="!re":
      intip=ip2int(attrs["=address"])
      if intip not in L:
        L.append(ip2int(attrs["=address"]))
    elif reply=="!done":
      None
    else: 
      sys.stderr.write("ERROR: navratova chyba: %s \n" % reply)


def pridej_do_dtb(cursor, L):
  """ Přidej do databáze IP adresy blokovaných.
  @param cursor: databázový kurzor
  @param L: seznam IP adres blokovaných
  """
  if L==[]: return
  cursor.execute("insert into spam_blokace (ip) VALUES (%s)" % ('),('.join(str(i) for i in L)))


def smaz_z_dtb(cursor,L):
  """ Smaž z databáze IP adresy blokovaných.
  @param cursor: databázový kurzor
  @param L: seznam IP adres ke smazání z blokovaných
  """
  if L==[]: return
  cursor.execute("delete from spam_blokace where ip in (%s)" % (','.join(str(i) for i in L)))


def kontrola_opakujici_se_blokace(cursor,cislo_smlouvy,ip):
  """ Kontroluje, jestli opakovaně neodesíláme informační email zákazníkovi. Informuje technika, pokud ano.
  Kontrola je určena pro vznik blokace, při ukončení blokace už tato kontrola není vhodná.
  @param cursor: databázový kurzor
  @param cislo_smlouvy: čislo smlouvy blokovaného
  @param ip: IP blokovaného
  """
  #pocet hlaseni o vzniku za poslednich 31 dni
  cursor.execute("""
    select count(*) from hlaseni
    where cislo_smlouvy=%d AND DATEDIFF(CURDATE(), datum)<31 and problem LIKE 'Aktivovana blokace SMTP na IP %s !%%'
    """ % (cislo_smlouvy, int2ip(ip)))
  pocet=int(cursor.fetchone()[0])

  if (pocet<1):
    #kontrolujeme po vlozeni hlaseni, tedy min. 1
    sys.stderr.write("ERROR nefunguje detekce opakujicich se blokaci!\n")
  elif (pocet<3):
    None
  elif (pocet>=3):
    #hlaseni technikovi
    problem="Z IP %s bylo za poslednich 31 dni uz %d krat detekovano rozesilani SPAMu. Pokud zakaznik problem neresi, nebude lepsi jej zablokovat trvale?" % (int2ip(ip), pocet)
    cursor.execute("""insert into hlaseni
      (platne_od,datum,cislo_smlouvy,problem,typ,vlozil,resitel) VALUES
      (CURDATE(),NOW(),%d,"%s","email","automat","technik");""" % (cislo_smlouvy,problem))
  else:
    sys.stderr.write("ERROR necekana chyba - pocet opakovani je %s !\n" % pocet)
    

def informovat(cursor,L,blokace):
  """ Vytvoří hlášení o aktivaci nebo zrušení blokace. Zákazníka informuje emailem, pokud je to možné.
  @param cursor: databázový kurzor
  @param L: seznam IP adres
  @param blokace: False|True True..nová blokace, False..blokace ukončena
  """
  if L==[]: return

  #texty do mailu a hlaseni
  if blokace:
    problem_template="Aktivovana blokace SMTP na IP %s !"
    mail_subject="SPAM - blokace"
    mail_text_template=TEMPLATE_BLOKACE
  else:
    problem_template="Zrusena blokace SMTP pro IP %s ."
    mail_subject="SPAM - blokace zrušena"
    mail_text_template=TEMPLATE_BLOKACE_ZRUSENA

  for ip_zak in L:
    sys.stdout.write("INFO %s blokace=%s\n" % (int2ip(ip_zak),blokace))
    #lokalni i routovane IP
    cursor.execute("""
      select cislo_smlouvy,aktivni from lokalni_ip where ip_adresa=inet_ntoa(%d)
      UNION
      select cislo_smlouvy,aktivni from routovane_ip where ip=%d
      """ % (ip_zak, ip_zak))
    cislo_smlouvy,aktivni=cursor.fetchone()
    problem=problem_template % int2ip(ip_zak)
    #mail zakaznika
    cursor.execute("""
      select e_mail,odpojen from zakaznici where cislo_smlouvy = %d
      """ % (cislo_smlouvy))
    email_zakaznika,odpojen=cursor.fetchone()

    #init
    reseni=""
    resitel="technik"
    vyrizeno=0
    #reseni a pripadne odeslani mailem
    if (odpojen==1):
      reseni="Zakaznik je odpojen, nebudu jej informovat. Pravdepodobne se jedna o zruseni dlouhodobe blokace."
      vyrizeno=1
      resitel=""
    elif (aktivni==0):
      reseni="Tato IP neni aktivni. Zakaznika nebudu informovat, pravdepodobne se jedna o zruseni dlouhodobe blokace."
      vyrizeno=1
      resitel=""
    elif not mail.kontrola_mailu(email_zakaznika):
      reseni="Zákazník nemá platný email. Především firemní zákazníky prosím informujte např. telefonicky."
    else:
      mail_text=mail_text_template % (int2ip(ip_zak))
      #mail zakaznikovi
      mail.send(fro='info@firma.example', to=email_zakaznika, subject=mail_subject, text=mail_text, charset='utf8')
      reseni="Zákazníkovi byla tato informace odeslána na email %s ." % email_zakaznika
      vyrizeno=1
      resitel=""

    #informacni hlaseni    
    cursor.execute("""insert into hlaseni
      (platne_od,datum,cislo_smlouvy,problem,reseni,vyrizeno,typ,vlozil,resitel) VALUES
      (CURDATE(),NOW(),%d,"%s","%s",%d,"email","automat","%s");""" % (cislo_smlouvy, problem, reseni, vyrizeno, resitel))

    #pri vzniku kontrolovat opakovani a pripadne nahlasit technikovi
    if blokace:
      kontrola_opakujici_se_blokace(cursor,cislo_smlouvy,ip_zak)


if __name__ == '__main__':
  if (getpass.getuser() != "statistiky"):
    sys.stderr.write("Tento skript smi pouzivat jen uzivatel statistiky.\n")
    sys.exit(1)

  try:
    opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
  except getopt.GetoptError as err:
    sys.stderr.write("%s\n" % str(err))
    usage(sys.stderr)
    sys.exit(1)
  for o in opts:
    if o[0] in ("-h", "--help"):
      usage(sys.stdout)
      sys.exit()

  if (len(sys.argv) != 1):
    usage(sys.stderr)
    sys.exit(1)

  conn=dtb.connect(charset="utf8", use_unicode=True)
  cursor=conn.cursor()

  cursor.execute("select ip_router from oblasti")
  rows=cursor.fetchall()
  L_RB=[]
  for row in rows:
    getBlock(L_RB,row[0])

  cursor.execute("select ip from spam_blokace")
  rows=cursor.fetchall()
  L_dtb=[]
  for i, in rows:
    L_dtb.append(int(i))

  #porovnani
  for i in L_RB[:]: #alespon melka kopie, jinach by se odmazavalo pod rukama
    if i in L_dtb:
      #je v obou, tak smazat
      L_dtb.remove(i)
      L_RB.remove(i)

  #ty co zustaly v L_RB, tak jsou nove
  pridej_do_dtb(cursor,L_RB)
  informovat(cursor,L_RB,blokace=True)

  #ty co zustaly v L_dtb, tak jsou zrusene
  smaz_z_dtb(cursor,L_dtb)
  informovat(cursor,L_dtb,blokace=False)

  cursor.close()
  conn.close()
