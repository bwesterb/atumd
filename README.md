atumd
=====

Post-quantum trusted time-stamping service.

Install using

```
go get github.com/bwesterb/atumd
```

Create a `config.yaml`:

```yaml
bindAddr: :8080
canonicalUrl: http://localhost:8080
```

and run

```
atumd
````

You probably want to configure a proper webserver like `nginx` to act
as proxy and set a corresponding sane `canonicalUrl` with HTTPS.

For more configuration options, see [config.yaml.example](config.yaml.example)

Clients
-------

 - [go-atumd](https://github.com/bwesterb/go-atum),
      Go client and Cli tool
