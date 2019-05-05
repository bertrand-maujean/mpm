# Master Password Manager

When planning the deployement of a password/secret manager, a Privileged Accounts Management solution, an Active Directory, or just a new server, the same question arise : how handle the master password of the password manager ?

A PAM software will definitely manage the every day's users passwords and identities. An administrative bastion will even deal with privileged identities. But what about the most privileged password of the bastion itself ?

When theses secrets are attached to a person, let this person find a solution. But when theses secrets remains "generic", like the "root" or "administrator" password, what do we do ? 

This is what "master password" means. We can think of "residual secrets".

Theses secrets are linked to emergency procedures that every organisation should consider.

This little software propose to manage theses residual secrets using the Shamir Secret Sharing Scheme. Like in a password manager, but to access the secret, a predefined "quorum" of persons must meet to "open their parts". A sort of vault is created, containing secrets, and "parts" are distributed to "holders". When holders meet and bring enough parts to raise the chosen threshold, they can view the stored secrets.

 ------------------------
# Features
- command-line only password manager, using a small set of commands and a completion/help feature
- Can store many secrets. Secrets can be organized in folders (but not too much, see below)
- Absolutely connection-less. Only a monolithic standalone executable and a database file. Suited for emergency procedures using a spare laptop on your knees between two rows in a datacenter. 
- The database file are totally encrypted, with no apparent structure. For someone who do not know about MPM, a database is like /dev/random (possible denial)
- Use strong crypto :
    - AES256/CBC for ciphering
    - SHA256 for hashing
    - An iterated SHA256 for key derivation (with a work and memory consumption proof)
- Build on Linux and Windows, only 64 bits (not tested on 32-bits system)
- Internationalization of command line messages (FR/EN for now)


---------------------
# Use cases. Things you can store in MPM database.
- **"administrator" password of an Active Directory** But do not forget to delegate capabilities to everyday sysadmins !
- **passphrase of a Keepass KDBX containing highly privileged generic secret** if you have a lot a residual secrets, it will be much more ergonomic.
- **passhrase of a privileged ssh key** For example, a specific identity used among several systems in the same emergency procedure.
- **key of a ecrypts/Veracrypt/bitlocker volume** for example, a directory/volume containing a root certification authority that is used only a few times a year.
- private key of a root certification authority

#### What it is not : ####
- a personal password manager.
- a high volume secret database
- a collaborative password manager. 

-----------------
# FAQ
**Is it an other password manager ?**
>Yes and no. MPM is a password manager but with a precise use case. It is optimized to manage the residual secret involved in emergency procedure. It is too little ergonomic to be used every days (but don't forget to train yourself about emergency procedures !)

**Why not just split a passphrase in several tokens given to separate persons ?**
>And what happen if one of theses persons leaves or dies ? If the secret is too small, given a part of it will lessen the space to explore for a brute force on the remaining parts. Using Shamir Secret Sharing, the knowledge of some parts, but below the decided threshold, does not bring you closer to the secret itself. To recover the secret, you do not need to bring together an exact set of person, but a quorum. If someone is missing, but someone else has a secret part too, no matter.

**Can it replace the location of a bank vault for my company ?**
>Yes, that is the idea. However, for now we suggest you still have a physical last level of recovery... And one more time : train your employees to execute emergency procedures. Think about the Mutually Assured Destruction doctrine : designed to be at the top of reliability, to be never used. 

**What about the database format ?**
>The binary file format is specific. It consist of "holder chunks" of 512 bytes at the beginning, one for each "holder". Each "holder chunk" begin with 3x32 bytes that are hashes used to recognize a valid "holder chunk". 
The remaining of the "holder chunk" is AES256-CBC ciphered.
After the "holders chunks" is the main database. it consist of a JSON stream, itself ciphered using AES256-CBC.
Consequently, the opening of a database can took several seconds because the program tries every 512-bytes block is order to test it. That is the price to hide the internal structure of the file.

**Why proposing several crypto / json backends at build time?**
At the beginning, I used GLIB for JSON and double-linked lists. But I realized that porting on Windows will be difficult because of GLIB. I found Jansson for JSON, and I did not remove the code for GLIB. Therfore, you have the choice. I did not try to use OpenSSL on Windows, but it is perhaps possible.

**Why is there no Visual Studio solution file ?**
Because I do not know very well VS. The IDE and "solution/project" concept is so big that I get lost. You have a specific Makefile suitable for nmake.

**Why not using gettext for internationalization ?**
Because I am novice in building on Windows, and the work to build my own internationalization routines was light enough.




------------

# Building

### Dependencies

MPM use some third parties software :
- [cli_parser](https://sourceforge.net/projects/cliparser/files/cliparser/0.5/) for the command line engine
- GLIB for the internal JSON handling (optionaly)
- [Jansson](http://www.digip.org/jansson/) as an alternative for JSON engine (optionaly, but must choose one of course)
- OpenSSL for the crypto engine on Linux
- Windows BCrypt API for the crypto on Windows

A few additional libraries from myself. I rewrote theses in order to avoid dependancies with other lib

- lb64 A small Base64 lib (see misc folder)
- tdll Tiny Double-Linked List (replacement for GLIB's glist_* API) (see misc folder)
- [lib_sss](https://github.com/bertrand-maujean/lib_sss) The main Shamir Sharing lib

### Building on Linux / GCC / gmake
See the Makefile.linux
Do not forget to install -dev packages (GLIB, GLIB-JSON...)

### Building on Windows / Visual Studio 2017 / nmake
Visual Studio 2017 Community
Use nmake with src/Makefile.win64
Don't forget to run first :
"c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
in order for VS to prepare the needed environment variables.
See misc folder for adapting cli_parser to Windows


### "DEBUG" switch and file
The "DEBUG" switch in Makefile trigger some debugging code. The program write a verbose "debug.out" file, and when saving the database, the json is dumped in clear in "mpm.debug.json". You can use this to understand the database format.
Warning : not for production use !



--------------------------

# Using / glossary / Demo

### MPM concepts

**Holder** 
> someone who participate in a use of a secret database. He defined a personal password, and can "free" his "parts of secret". Holders have a 'number of parts' that can be changed (default to 1).

*note on the number of parts* the number of parts that an holder can hold is limited to 8, for 'common level' plus 'secret level'. Whereas the common and secret threshold are treated separately, the limit apply to the sum. This is a format limitation in the database. Anyway, it is not expected that you use more than 2-3 parts for each holder in each level.

**Level**
> The database can be opened at different "Level" :

- *Closed* The database is given by it's file name, but it is not possible to distinguish it from random bytes. Prompt is "?"
- *First* An holder unlocked his parts, and it works. So we are almost sure that the given file really is an MPM database. We also know how many holders there are, and the threshold needed. But at this level, the database is still inaccessible. Prompt is "!".
- *Common* The threshold for the "common" level is raised. The structure of the database is visible : titles, folders, non-secret fields. All the holders, including those who didn't release their parts, are visible. Prompt is ">"
- *Secret* The secret fields are accessible. It is possible to add or delete holders, secrets. Prompt is "#".


**Secret**
> Like a form, with a title and optional fields. Secrets are stored in folders. Secret have an index showed by 'ls' command. You must use this index to use a secret in a command. You cannot designate a secret by its title.


**Folders**
> Secret are stored in folders. Use command 'ls' (list secret) to see what secrets exist in the current folder. Like in a filesystem. Use 'cd' to enter a subfolder, or 'cd ..' to enter the parent folder. But there is a small limitation : you can not use the folder title, you must use the numeric index given by 'ls' command.

**common threshold** and **secret threshold**
> In fact, there are two instances of secret sharing. The 'common' one is used to encrypt the database. The 'secret' one is used to additionally encrypt the fields that are declared 'secret'. Using this two level, you can have a threshold that can permit people to see that the needed secret really is in this database, and only then, request for an additional holder.

**Database naming**
> You can use any name and extension that you want. In the demo folder, I use '.mpm' extension.

### Opening an existing database

To reach the 'common level' :
```
H:\ber\mpm\build\win>mpm ..\..\demo\truc.mpm
truc.mpm? try riri
        Give password for 'riri' :
Ok. riri brought 1/1 parts.
truc.mpm! try fifi
        Give password for 'fifi' :
Ok. fifi brought 1/1 parts.
truc.mpm>
```
Now we have he ">" prompt. We can see the database structure :
```
truc.mpm> ls
Current folder [1] Racine

Sub-folders :

Secrets :
[3] autre secret

truc.mpm>
```
But secret fields are still masked :
```
truc.mpm> show secret 3
Secret [3] : autre secret
Content :
        [user] : duchnok
        [url] : http://bidule.truc.tld
        [pwd] : Database not open at 'secret' level
truc.mpm>
```

We can see what other holders exists :
```
truc.mpm> show holders
Holders who's parts are available (nickname / number of common parts / nb secret parts / e-mail)
        riri 1 / 1
        fifi 1 / 1
Holders who released their parts :
        loulou 1 / 1
        ber 1 / 1

Total number of detected holders : 4
```

Opening at the "secret" level :
```
truc.mpm> try loulou
        Give password for 'loulou' :
Ok. loulou brought 1/1 parts.
truc.mpm#
```
We now have the "#" prompt. We can see secret fields :
```
truc.mpm# sh sec 3
Secret [3] : autre secret
Content :
        [user] : duchnok
        [url] : http://bidule.truc.tld
        [pwd] : kjjkhjhjklhjcnszopckl
```


### Creating a new database
Creating the new database. We have to decide now the thresholds for the two level 'common' and 'secret' :
```
H:\ber\mpm\demo>mpm

(none) init file demo.mpm common parts 2 secret parts 3
New database initialization
- File name : 'demo.mpm'
- Treshold for 'common' level : 2
- Treshold for 'secret' level : 3
```

Adding an holder :
```
*demo.mpm# new holder riri
        Give a password for this holder :
        Confirm password :
        New holder created (id=1 riri). His parts are available, and you can change their quantity.
```

Checking the database state :
```
*demo.mpm# check
Database opened at 'secret' level. Everything is editable. Holder add/remove is possible.

Number of parts :
              Avail.   Needed   Given
common:          1         2         1
secret:          1         3         1

Warning : Number of given parts just equal or below number of needed parts. You should distribute some more parts in order to recover the database in case of empediment of a holder

Database has been changed.    (holders)  (new base)
```
Obviously, we did not distribute enough parts !

Adding other holders as previously.

Adding a new secret :
```
demo.mpm# new secret
Give a title for this new secret : Local root password of the bastion server
id for the new secret : 2
*demo.mpm#
```

Updating/creating the field "pwd" for this new secret, and set it "secret" (so it can only be view in "secret" level) :
```
*demo.mpm# edit secret 2 update field pwd
Current field value [pwd] :kjjkhjhjklhjcnszopckl
Give the new value for this field : abcdef

*demo.mpm# edit secret 2 secret
<STRING:field_name>
*demo.mpm# edit secret 2 secret pwd
```

Save the database :
```
*demo.mpm# save
Warning :
Sauvegarde du fichier : demo.mpm - Fait
```



### Demo database
In the 'demo' folder : demo.mpm
Holder nicknames are : riri, fifi, loulou, donald. Password are identical to nicknames.
Come with compiled binaries : mpm.exe for Windows and mpm (elf64) for Linux64.



-----------------------
# TODO / new features
- "launcher" concept. Instead of viewing a secret, use information inside it to launch a command
- Suggested launchers : open a Keepass (Windows/Linux), "su" on Linux, ssh-agent, putty-agent, mount -t ecrypts, dm-crypt/luks, runas (Windows)... Every way to elevate in an emergency procedure.
- Write notes on building Jansson and cli_parser on Windows. Propose Windows changes to the owner of cli_parser.



--------------------------
# Acknowledgements
- Petri Lehtinen for [jansson](http://www.digip.org/jansson/) and it's simple and clear API
- Henry Kwok for [cli parser](https://sourceforge.net/projects/cliparser/)

------------------------
# Licence
This program is released under the terms of the GNU GPLv3 License.
It comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
See LICENSE.txt file, and equivalent information in the cliparser and Jansson libraries.

MPM 'Master Password Manager' Copyright (C) 2018-2019 Bertrand MAUJEAN


