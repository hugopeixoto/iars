# IndieAuth provider

An [IndieAuth](https://indieauth.net/) provider you can self-host to be able to
login using your own domain.

It currently implements the metadata endpoint needed for
`rel=indieauth-metadata` and `rel=authorization_endpoint`. I'll probably
simplify this to only support the authorization endpoint and leave the
discovery mechanism to the user.


## Instructions

1. Pick a domain name where iars should run (it can be a subdomain of your identity or any other domain you control)
1. Create a config file in your server (see below)
1. Get `iars` running on your server using `systemd` or something
1. Configure nginx / apache2 / whatever with HTTPS to serve requests to the domain you picked in step 1 using `iars`
1. Add `<link rel="authorization_endpoint" href="https://your-iars-domain/authorize" />` to your homepage's index file
1. Add `<link rel="indieauth-metadata" href="https://your-iars-domain/metadata" />` to your homepage's index file
1. Done!


## Security

`iars` authenticates you using TOTP. This is not super secure. To prevent
someone from brute-forcing it, after three failed authentication attempts, this
program stops accepting them and you need to manually restart the server to
reset this counter.

I'm probably removing this in favor of something like unifiedpush.org. I may
keep a password-only option as well, don't know yet.


## Configuration

`iars` uses a TOML configuration file. The location of this file is passed
using an environment variable `IARS_CONFIG_FILE`. The file must contain the
following keys:

```toml
base_url = "https://iars.pxto.pt/" # used to populate the metadata endpoint
me = "https://hugopeixoto.net/"    # your identity domain
totp_secret = "randombase32secret" # secret key used to authenticate via TOTP
listen_address = "127.0.0.1"
listen_port = 8080
```

The `totp_secret` value can be generated by running `iars generate-secret`, and
you can add it to your authenticator mobile app (something like Aegis works
fine).
