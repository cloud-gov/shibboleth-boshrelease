# [WIP] BOSH Release for shibboleth

This is a WIP identity provider suitable for use as a SAML provider in CloudFoundry.

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
        -----BEGIN RSA PRIVATE KEY-----
        -----END RSA PRIVATE KEY-----
      cert: | # Specifies your public SAML certificate.
        -----BEGIN CERTIFICATE-----
        -----END CERTIFICATE-----
    encryption:
      key: | # Specifies your private SAML encryption key
        -----BEGIN RSA PRIVATE KEY-----
        -----END RSA PRIVATE KEY-----
      cert: | # Specifies your public SAML encryption certificate.
        -----BEGIN CERTIFICATE-----
        -----END CERTIFICATE-----
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

> *TODO*

## Usage

To use this bosh release, first upload it to your bosh:

```
bosh target <BOSH_HOST>
git clone https://github.com/cloudfoundry-community/shibboleth-boshrelease.git
cd shibboleth-boshrelease
bosh upload release ./releases/shibboleth/shibboleth-1.yml
```

For [bosh-lite](https://github.com/cloudfoundry/bosh-lite), you can quickly
create a deployment manifest & deploy a cluster. Note that this requires that
you have installed [spruce](https://github.com/geofffranks/spruce).

```
./templates/make_manifest warden
bosh -n deploy
```

For AWS EC2, create a single VM:

```
./templates/make_manifest aws-ec2
bosh -n deploy
```

### Override security groups

For AWS & Openstack, the default deployment assumes there is a `default`
security group. If you wish to use a different security group(s) then you can
pass in additional configuration when running `make_manifest` above.

Create a file `my-networking.yml`:

``` yaml
---
networks:
  - name: shibboleth1
    type: dynamic
    cloud_properties:
      security_groups:
        - <SECURITY_GROUP_NAME>
```

You now suffix this file path to the `make_manifest` command:

```
./templates/make_manifest openstack-nova my-networking.yml
bosh -n deploy
```

### Development

As a developer of this release, create new releases and upload them:

```shell
bosh create release --force && \
bosh -n upload release
```

### Final releases

To share final releases:

```shell
bosh create release --final
```

By default the version number will be bumped to the next major number. You can
specify alternate versions:


```shell
bosh create release --final --version 2.1
```
