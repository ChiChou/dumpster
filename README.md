# dumpster

Glue project to build your IPA decryptor workflow. 
Project name does not matter, there are even projects called hooker or something.

## Prerequisites

Jailbroken iPhone

Check [tweak](tweak/README.md)

Server

* [ipatool](https://github.com/majd/ipatool)
* [libimobiledevice](https://libimobiledevice.org/)
* Python and [uv](https://docs.astral.sh/uv/)

## Set Up SSH

Edit `~/.ssh/config` to add your device, for example:

```
Host ios
    LogLevel ERROR
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyCommand inetcat 22
    User mobile
```

You can add `--udid` to inetcat parameters if you have multiple devices.

Make sure that you can `ssh ios` without password prompt now. You need to supply this "ios" as host name param to the script.

## Workflow

Download ipa with ipatool. Then

`uv run app.ipa root@ios`

If all goes well, the result will be in app.decrypted.ipa
