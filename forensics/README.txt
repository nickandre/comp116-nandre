Assignment 5 for Nick Andre and Kezhi Wu  


Part1


1. We use ls -l command which shows that picture a.jpg is of different size
than others. So we ran strings on a, got nothing; opened with text editor, 
got nothing; Then we use steghide tried with no password and got a file 
named prado.jpg with another picture of Norman. We wrote a bash script try to brute force through the password using a normal dictionary as wordlist just to be sure, and there was nothing.


Part2


1. FS type is ext4 root and vfat boot


2.  couldn’t find a carrier. Appears to be a Raspberry Pi OS.


3. We mount the disks and goto /etc/os-release. it prints 
PRETTY_NAME="Kali GNU/Linux 1.0"
NAME="Kali GNU/Linux"
ID=kali
VERSION="1.0"
VERSION_ID="1.0"
ID_LIKE=debian
ANSI_COLOR="1;31"
HOME_URL="http://www.kali.org/"
SUPPORT_URL="http://forums.kali.org/"
BUG_REPORT_URL="http://bugs.kali.org/"




4. goto usr/bin  usr/sbin which shows all applications installed.
examples like,
arpspoof
dnsspoof
dsniff
sniffjoke
metaspolit(found in /opt)
teeth(found in /opt)




5.yes. password is “toor”. Brute forced passwrd/shadow file using john with default options and no wordlist.


6. yes. the passwd file from /etc/ shows multiple user accounts


7. We have uncovered many pics of Celine Dion by doing foremost on jpeg. 
We also found a ticket receipt to one of her concert.


8. yes. Using autopsy reveals deleted files. We also pull all the files using foremost which i think includes the deleted files. eg.  “foremost -t all -i sdcard.dd”


9. We found several suspicious files whose extension did not match the file description. We had a lot of trouble compiling TrueCrack because neither partner had an appropriate NVidia graphics card and were unable to reveal the contents.


10.yes. We found a ticket master recept in all of the pdf files we pull using foremost. 


The Colosseum At Caesars Palace, Las Vegas, NV
Sat, Jul 28, 2012 07:30 PM


11. In addition to the images etc, there were several suspicious files as well as many sniffing utilities which raise suspicions about the intents of the owner.




12. Celine Dion