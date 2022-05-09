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

`iars` authenticates you using https://ntfy.sh. When you press "consent", `iars`
sends a push notification to your ntfy endpoint containing two actions,
authorize and deny, and waits for a response in another `iars` endpoint. Picking
any action (presumably on your phone) will issue a POST back to `iars` and the
initial request gets unblocked. If you don't answer within 30 seconds, the
original request times out.

To prevent someone from brute-forcing things, after three consecutive timed out
authentication attempts, `iars` stops accepting them and you need to manually
restart the server to reset this counter.

Anyone able to read the ntfy topic will be able to impersonate you. Be
sure you either use something you trust or self-host it yourself.


## Configuration

`iars` uses a TOML configuration file. The location of this file is passed
using an environment variable `IARS_CONFIG_FILE`. The file must contain the
following keys:

```toml
base_url = "https://iars.pxto.pt/" # used to populate the metadata endpoint
me = "https://hugopeixoto.net/"    # your identity domain
listen_address = "127.0.0.1"
listen_port = 8080
unifiedpush_endpoint = "https://ntfy.sh/edad099e380a6cbf4c30b8e6d9939426f9b39ec34682016b719e484d01975a49"
```

The ntfy endpoint should be kept secret, as anyone who is able to read from it
will be able to impersonate you. In this example I'm using `ntfy.sh`, which
requires you to trust the operators of that service. You can self-host an
instance of nfty if you prefer.


## Improvements

- reduce the number of mutex operations
- configure 30secs timeout via TOML
- make form pretty
- render error pages
- /answer code
- use a custom android app to actually use unifiedpush instead of ntfy and be able to use secrets instead of passing them in cleartext via the push notification, but, urgh
