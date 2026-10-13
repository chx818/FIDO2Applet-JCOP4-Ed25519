# Installation Parameters

This applet provides a variety of install-time configurable settings. These are configured via a
CBOR map provided when the applet is installed (for example, via `gp --install <applet> --params <params>`).

To generate the parameter string, use the `get_install_parameters.py` script at the root of the repository.
The help the script provides (`--help`) explains each options.

This fork defaults to maximum FIDO standards compatibility and permits first-use
attestation provisioning without an install option. `A100F4` explicitly locks the
applet to self-attestation. U2F still requires installing a P-256 attestation identity
before creating credentials. Reset preserves an already provisioned identity.

If you want attestation to work, you'll also need to run `./install_attestation_cert.py` after installing the
applet itself!

## Android installation

For the Android installation to work with the native system UI provided by the Google Play Services, the
applet needs to be the default selected applet on the card.

You can do that with `gp --install <applet> --params <params> --privs CardReset`

The reason is that Google Play Services send the `SELECT` APDU using extended-length encoding while the
GlobalPlatform manager of JavaCards does not support that.
By having the applet be the default selected applet, it can bypass GlobalPlatform and handle the `SELECT`
by itself.


## Existing multi-applet cards (this fork)

`CardReset` is an optional deployment choice for clients that need the default-selected
route described above. Clients that explicitly select the FIDO AID may not need it.
Do not delete an unknown preinstalled applet or package just to obtain this privilege.
On a card with an existing default-selected application, first verify the actual client
path and the vendor-supported configuration. The experimental card changes described
in the local audit are not a general installation recipe.
