# Zanim zaczniemy
1. Na Kali
```
sudo apt-get update
```

```
git clone https://github.com/sszkarlat/projekt-sieci.git 
```

```
cd projekt-sieci
make all
```

Instalacja między innymi openssl
```
sudo apt-get install libssl-dev
```

```
make all
```

2. Na Ubuntu
```
sudo apt update
```

```
sudo apt install git
```

```
git clone https://github.com/sszkarlat/projekt-sieci.git 
```

```
sudo apt install make
```

```
sudo apt install build-essential
```

```
sudo apt install libssl-dev
```

```
make all
```

# Opis działania

1. Uruchomienie serwera
```
./serwer
```

Uruchamiamy serwer. Jak widać w logach, serwer startuje, nasłuchuje na połączenia TCP oraz na zapytania multicast do odkrywania usługi. Działa on teraz w tle jako demon.

2. Odkrywanie serwera przez pierwszego klienta

```
./client -discover
```

Uruchamiamy pierwszego klienta z flagą -discover. Zamiast podawać adres IP, klient wysyła w sieć lokalną zapytanie multicast. Serwer na nie odpowiada, a klient, jak widać, automatycznie go znajduje i nawiązuje połączenie.

3. Rejestracja i logowanie pierwszego użytkownika

```
register user1 pass1
```

Najpierw musimy zarejestrować nowego użytkownika. Tworzymy konto dla user1. Serwer potwierdza, że rejestracja się powiodła. Hasło jest hashowane algorytmem SHA256 i zapisywane na serwerze, w pliku ```users.dat```. Możemy to podejrzeć w innym terminalu, że hasło jest trzymane jako hash.

```
login user1 pass1
```

Teraz logujemy się na nowo utworzone konto. Serwer weryfikuje poświadczenia i potwierdza udane logowanie.


4. Dołączenie drugiego klienta

Aby dołączyć po adresie IP, podajemy adres IP serwera.
```
./client 192.168.110.139 
```

Teraz uruchamiamy drugiego klienta. Tym razem dla uproszczenia podajemy adres serwera ręcznie. Ten klient również nawiązuje połączenie z serwerem.

```
register user2 pass2
```

```
login user2 pass2
```

Drugi użytkownik, user2, również przechodzi proces rejestracji i logowania.

5. Prezentacja czatu w czasie rzeczywistym

Teraz najważniejsza część – komunikacja. Gdy user1 wyśle wiadomość, serwer rozgłosi ją przez multicast do wszystkich podłączonych klientów. Proszę obserwować oba terminale klientów.

```
send user2 Cześć, tu user1! To jest test.
```

Jak widać, wiadomość wysłana przez user1 pojawiła się natychmiast u obu użytkowników, co potwierdza działanie czatu multicast w czasie rzeczywistym.

```
send user1 Wszystko działa!
```

Odpowiedź od user2 również dociera do wszystkich w tym samym momencie.

6. Prezentacja historii czatu
Każda wiadomość jest archiwizowana na serwerze. Teraz user1 pobierze historię swojej rozmowy z user2.


```
history user2
```

Klient wysłał prośbę do serwera, a serwer odesłał zapisaną historię, która została wyświetlona na ekranie. Potwierdza to, że mechanizm archiwizacji i odczytu historii działa poprawnie.


7. Zakończenie i podsumowanie
Na koniec użytkownicy mogą się wylogować i zakończyć pracę.

```
quit
```

Po rozłączeniu klientów, serwer wciąż działa i jest gotowy na przyjęcie nowych połączeń. Możemy go zatrzymać, wysyłając sygnał Ctrl+C.

Serwer poprawnie obsługuje sygnał zamknięcia.
