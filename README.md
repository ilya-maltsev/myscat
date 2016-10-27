# myscat - MySQL general-log parser

Инструкция по комплиляции в Centos 6:

1) в ОС нужно установить Perl-libs:
sudo yum install pcre-devel -y

2) сам парсер собирать командой:
gcc -Wall -o /develop/myscat4 /develop/myscat.c -lpcre

----
Инструкция по использованию

1) создаем pipe:
mkfifo /var/log/mysql/pipe-log

2) создаем init-скрипт:
vim /etc/init/myscat.conf

start on runlevel [2345]

respawn
script

/usr/bin/stdbuf -oL /develop/myscat4 /var/log/mysql/pipe-log >> /var/log/mysql/mysql_parsed_log.log

end script

3) запускаем службу:
initctl start myscat

Пояснение:
все, что будет отправлено демоном mysqld в /var/log/mysql/pipe-log будет проанализировано парсером, а результат попадет в файл /var/log/mysql/mysql_parsed_log.log
