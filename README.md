atumd
=====

Post-quantum trusted time-stamping service.
See [go-atum](https://github.com/bwesterb/go-atum) for more information
on the protocol.

Setup
-----
To install `atumd`, run

```
go get github.com/bwesterb/atumd
```

Then create a `config.yaml`:

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

Warnings concerning redundancy and backups
------------------------------------------

`atumd` uses the **statefull** XMSS[MT] Siganture scheme.  Each signature
has a *sequence number* (seqno) and a sequence number
[must not](https://eprint.iacr.org/2016/1042.pdf) be reused as it
is likely to lead to signature forgery.
A private key has a largest sequence number which depends on the
instance of the scheme.  The first free sequence number is stored in the
XMSSMT private key file.  Thus

- **Do not copy** the XMSSMT private key file, for then the same signature
  sequence number might be reused.
- In particular, **do not restore** a keyfile from a backup.

Instead of **backups**, simply generate a new XMSSMT keypair for your atumd
server if the old one gets corrupted.  You can add the old public key to
the `otherTrustedPublicKeys` list in the configuration so that signatures set
by the old public key remain trusted.

Instead of copying the key for **redundant copies** of the server, create
a new keypair for each server and again add the different public keys to
the `otherTrustedPublicKeys` of all servers.

Clients
-------

 - [go-atum](https://github.com/bwesterb/go-atum),
      Go client and Cli tool
