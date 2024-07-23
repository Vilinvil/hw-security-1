**Ильинский Владислав**

[Телеграм для связи](https://t.me/Vilin0)

[Условия задачи](https://docs.google.com/document/d/1QaQ-Nc_eE4dBKZwQbA4E2o8pOJ3CktgsKDAn375iY24/edit)

### Генерация сертификатов
```shell
make gen-cert
```

Для работы нужно добавить их в систему, на ubuntu:
```shell
sudo apt-get install -y ca-certificates
sudo cp certs/ca.crt /usr/local/share/ca-certificates
sudo update-ca-certificates
```

### Собрать проект
```shell
make build
```

### Поднять проект
```shell
make up
```
