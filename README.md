# sparsebundlefs-lib
==============

Library to read encrypted and clear Mac Osx sparsebundle

## Purpose
Provide a simple access to osx sparsebundle, encrypted or not.
API is very simple :
* open
* read similar to pread
* close

## Encryption
For encrypted sparsebundle, crypto functions are need.
* to use openssl, define SPARSEBUNDLEFS_USE_OPENSSL<br/>
In that case, you only need one file to compile : sparsebundlefs.c (you can rename it sparsebundlefs.cpp)
* to use the embedded crypto, define SPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO. This is the default.<br/>
Along with sparsebundlefs.c, compile all the file found in src/crypto. This is things I found on the internet. I kept the fastest one I know.
* to force not using any crypto, define SPARSEBUNDLEFS_NO_CRYPTO.<br/>
Encrypted sparsebundle won't mount. Mounted like this, an encrypted sparsebundle won't be usable because of the lack of encrypted header, which is supposed to be at the beginning of the file. With sparsebundle, it's in a separate file called token.

## Suggestion how to use it
You can use this git command to get only what's needed in your project.

* git clone --no-checkout https://github.com/jief666/sparsebundlefs-lib.git
* cd sparsebundlefs-lib/
* git config core.sparseCheckout true
* echo "src/sparsebundlefs" >> .git/info/sparse-checkout
* echo "src/crypto" >> .git/info/sparse-checkout  <- only if you want embedded crypto.
* git checkout master <- should say : Already on 'master'. Your branch is up to date with 'origin/master'.

## Fuse
There is a simple fuse implementation. It allows you to see a file "sparsebundle.dmg" in the fuse mount point. You can then use tools of your os to mount the dmg, depending on what file system there is on it.
See https://github.com/torarnv/sparsebundlefs for how to use it.<br/>
This was with the original project I took. It's **not** the goal of that small project.

## Why
I wanted to add sparsebundle ability in other project that can already read dmg. I also wanted to be able to use that on low ressources linux machine.<br/>
That's why I had to take the original project from Tor Arne Vestbø and separate the fuse part from the sparsebundle access part. Also, Tor Arne Vestbø doesn't want to integrate encryption in his project. He wants to keep things separated. He thinks that the sparsebundle should be mounted and then read and decrypted (and mounted if needed) by antoher tool. Basically the mount.hfs that you have on linux. This makes a lot of sense, but...<br/>
The probem with that is that mount.hfs is partially implemented, at least on my linux (no HFS compressed file, for example). I could use some open source tools to remount the dmg as a file system. But that would mean a fuse mount over another fuse mount which doesn't seem like an amazing idea on low ressources machine.

## Credit
This project comes from https://github.com/torarnv/sparsebundlefs by Tor Arne Vestbø.

