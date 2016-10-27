# myscat - MySQL general-log parser

## Описание

Данная программа предназначена для фильтрации general-log'а СУБД MySQL с целью получения информации о вносимых изменения в структуру и состав таблиц БД. Недостатком исходного формата general-log'а является наличие мультистрочности запросов и отсутсвие информации о пользователе, от чьего имени был выполнен запрос (указывается только id его сессии).

## Пример
следующие строки 
```sh
160912 10:02:23   167 Connect   service-user@app1.domain.test on logs_1
          167 Connect   service-user@app1.domain.test on logs_archive_by_day
          167 Query SET NAMES cp1251
          167 Query SET NAMES 'UTF8'
          167 Query CREATE TABLE IF NOT EXISTS logs_archive_by_day.2016_09_12(
                      log_id  int(10) unsigned NOT NULL DEFAULT 0,
                      firm_id int(10) unsigned NOT NULL DEFAULT 0,
                      user_id int(10) unsigned NOT NULL DEFAULT 0,
                      admin_id int(10) unsigned NOT NULL DEFAULT 0,
                      postData text,
                      getData text,
                      cookieData varchar(1000) NOT NULL DEFAULT "",
                      title varchar(255) NOT NULL DEFAULT "",
                      content mediumtext,
                      ip int(11) NOT NULL DEFAULT 0,
                      host_name varchar(60) NOT NULL DEFAULT "",
                      http_host varchar(20) NOT NULL DEFAULT "",
                      url varchar(255) NOT NULL DEFAULT "",
                      userAgent varchar(255) NOT NULL DEFAULT "",
                      locale varchar(10) NOT NULL DEFAULT "",
                      marker varchar(255) NOT NULL DEFAULT "",
                      request_time datetime NOT NULL,
                      created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                      KEY idx_log_id(log_id),
                      KEY idx_user_and_firm (user_id,firm_id, admin_id, request_time)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8
```
        
        
будут преобразованы в следующую строку

```160912 10:02:23 service-user@app1.domain.test Query       CREATE TABLE IF NOT EXISTS logs_archive_by_day.2016_09_12(  log_id int(10) unsigned NOT NULL DEFAULT 0,  firm_id int(10) unsigned NOT NULL DEFAULT 0,  user_id int(10) unsigned NOT NULL DEFAULT 0,  admin_id int(10) unsigned NOT NULL DEFAULT 0,  postData text,  getData text,  cookieData varchar(1000) NOT NULL DEFAULT "",  title varchar(255) NOT NULL DEFAULT "",  content mediumtext,  ip int(11) NOT NULL DEFAULT 0,  host_name varchar(60) NOT NULL DEFAULT "",  http_host varchar(20) NOT NULL DEFAULT "",  url varchar(255) NOT NULL DEFAULT "",  userAgent varchar(255) NOT NULL DEFAULT "",  locale varchar(10) NOT NULL DEFAULT "",  marker varchar(255) NOT NULL DEFAULT "",  request_time datetime NOT NULL,  created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,  KEY idx_log_id(log_id),  KEY idx_user_and_firm (user_id,firm_id, admin_id, request_time) ) ENGINE=InnoDB DEFAULT CHARSET=utf8```


которую в дальнейшем будет легко распарсить и сохранить в БД

----
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

```sh

start on runlevel [2345]

respawn
script

/usr/bin/stdbuf -oL /develop/myscat4 /var/log/mysql/pipe-log >> /var/log/mysql/mysql_parsed_log.log

end script
```

3) запускаем службу:
initctl start myscat

## Пояснение:
все, что будет отправлено демоном mysqld в /var/log/mysql/pipe-log будет проанализировано парсером, а результат попадет в файл /var/log/mysql/mysql_parsed_log.log
