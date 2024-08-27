# BOSH Release for Shibboleth v4

This is an identity provider suitable for use as a SAML provider in CloudFoundry.

## Configuring the IdP tomcat instance

By default tomcat is configured to use SSL with a self-signed certificate and will be started on port 8443.

### Using your own certificate

Add the following properties to a file called `my-secrets.yml`:

``` yaml
---
properties:
  idp:
    sslCertificate: | # Specifies your SSL certificate
        -----BEGIN CERTIFICATE-----
        YOUR CERT HERE
        -----END CERTIFICATE-----
    sslPrivateKey: | # Specifies your private key. The key must be a passphrase-less key.
        -----BEGIN RSA PRIVATE KEY-----
        YOUR KEY HERE
        -----END RSA PRIVATE KEY-----
```

### Generating a self-signed certificate

1. Generate your private key with any passphrase

```shell
openssl genrsa \
        -aes256 \
        -out server.key \
        1024
```

2. Remove passphrase from key

```shell
openssl rsa \
        -in server.key \
        -out server.key
```

3. Generate certificate signing request for CA

`openssl req -x509 -sha256 -new -key server.key -out server.csr`

4. Generate self-signed certificate with 365 days expiry-time

```shell
openssl x509 \
        -sha256 \
        -days 365
        -in server.csr \
        -signkey server.key \
        -out selfsigned.crt
```

### Create the SAML Signing Key and Certificate

The main key underlying most IdPs is the digital signing key. This is a private
key used to sign SAML messages.  The certificate is just a convenient container
for the public key. In Shibboleth, or any compliant SAML system, the content of
the certificate other than the key is totally ignored.

> Protect your private signing key!
> Make no mistake, a compromised signing key allows anybody with the key to impersonate your IdP and by extension all of its users.

1. Generate your SAML signing key and certificate

```shell
openssl req -new \
            -x509 \
            -nodes \
            -newkey rsa:2048 \
            -keyout key.pem \
            -days 365 \
            -subj '/CN=hostname.example.org' \
            -out cert.pem
```

Add the following properties to the `my-secrets.yml` file:

```yaml
---
properties:
  idp:
    signing:
      key: | # Specifies your private SAML signing key
        YOUR KEY HERE
      cert: | # Specifies your public SAML certificate.
        YOUR CERT HERE
    encryption:
      key: | # Specifies your private SAML encryption key
        YOUR KEY HERE
      cert: | # Specifies your public SAML encryption certificate.
        YOUR CERT HERE
```

You now suffix this file path to the `make_manifest` command:

```
./templates/make_manifest warden my-secrets.yml
bosh -n deploy
```

### Notes

- The property `idp.port` can't be set to `8989` because this port is used by
  BOSH to monitor the server.

## Using the UAA database with shibboleth for authentication

For more information on how to leverage a UAA database, please see the
[cg-deploy-shibboleth][cg-deploy-shibboleth] documentation which leverages this
release.

## Usage

See [cg-deploy-shibboleth][cg-deploy-shibboleth] for a sample deployment.

[cg-deploy-shibboleth]: https://github.com/cloud-gov/cg-deploy-shibboleth "cloud.gov Concourse deployment pipeline for cloud-gov/shibboleth-boshrelease"
