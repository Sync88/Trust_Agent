# Keylime Trust Agent Installation 

This repository contains code for running the Keylime Trust Agent, one of the three major components of the Keylime trust system.

The Trust Agent should be installed on the remote machine that is to be measured or provisioned with secrets stored within an encrypted payload delivered once trust is estabilished.
haedware section of your virtual machine. n order to do this you have to install swtpm on your host machine. Use the CRB mode, selecting an emulated device for a TPM 2.0)

(if you are using a virtual machine on KVM, remember to add a TPM in the hardware section of your virtual machine. In order to do this you have to install swtpm on your host machine. Use the CRB mode, selecting an emulated device for a TPM 2.0)


# from tpm2-tss INSTALL.md

Dependencies

To build and install the tpm2-tss software the following software packages are required. In many cases dependencies are platform specific and so the following sections describe them for the supported platforms.
GNU/Linux:

    GNU Autoconf
    GNU Autoconf Archive, version >= 2017.03.21
    GNU Automake
    GNU Libtool
    C compiler
    C library development libraries and header files
    pkg-config
    doxygen
    OpenSSL development libraries and header files
    libcurl development libraries
    Access Control List utility (acl)

        git clone https://github.com/tpm2-software/tpm2-tss.git tpm2-tss

        $ sudo apt -y update
        $ sudo apt -y install \
        autoconf-archive \
        libcmocka0 \
        libcmocka-dev 
        procps 
        iproute2 
        build-essential 
        git 
        pkg-config 
        gcc \
        libtool 
        automake \
        libssl-dev 
        uthash-dev 
        autoconf \
        doxygen \
        libjson-c-dev \
        libini-config-dev \
        libcurl4-openssl-dev \
        acl \
        libglib2.0-dev

        sudo ./bootstrap
        sudo ./configure  
        sudo make -j $(nproc)
        sudo make install


# from tpm2-abrmd INSTALL.md

        Below the dependencies needed:
        • GNU Autoconf
        • GNU Autoconf archive
        • GNU Automake
        • GNU Libtool
        • C compiler
        • C Library Development Libraries
        • pkg-config
        • glib and gio 2.0 libraries

        The daemon tpm2-abrmd can run as tss user or root. As common security
        practice the daemon can be run as unpriviliged user, which requires creating a
        user account and group. The account and associated group must be created before
        running the daemon as follow:

        $ sudo useradd --system --user-group tss

        $ git clone https://github.com/tpm2-software/tpm2-abrmd.git
        $ ./bootstrap
        $ ./configure --with-dbuspolicydir=/etc/dbus-1/system.d 
        $ sudo make
        $ sudo make install
        $ sudo ldconfig


# from tpm2-tools INSTALL.md

        sudo apt-get install python-yaml

The libcurl dependency can be satisfied in many ways, and likely change with Ubuntu versions:

    libcurl4-openssl-dev 7.47.0-1ubuntu2.2
    libcurl4-nss-dev 7.47.0-1ubuntu2.2
    libcurl4-gnutls-dev 7.47.0-1ubuntu2.2


- GNU Autoconf (version >= 2019.01.06)
- GNU Automake
- GNU Libtool
- pkg-config
- C compiler
- C Library Development Libraries
- ESAPI - TPM2.0 TSS ESAPI library
- OpenSSL libcrypto library
- Curl library

        git clone https://github.com/tpm2-software/tpm2-tools
        cd tpm2-tools
        ./bootstrap
        ./configure 
        make -j $ (nproc)
        sudo make install


(###ho avuto un piccolo problema con il simulatore dell'TPM da aggiungere a KVM. E' bastato ricompilare e instllare swtpm sull'host)


Once you have installed these 3 components reebot your system.

## install the trust agent

        $ git clone https://github.com/Sync88/Trust_Agent.git
        $ cd Trust_Agent
        $ cd Agent 


        install the needed dependencies 

        sudo apt install python3-pip
        sudo apt install python3-tornado
        sudo apt-get install libssl-dev swig python3-dev gcc
        sudo apt-get install python3-gnupg


        (sulla schedina ho fatto 


                $ sudo apt install python3-pip
                $ sudo apt install python3-tornado
                $ sudo apt update
                $ sudo apt-get install libssl-dev swig python3-dev              
                $ sudo apt install python3-gnupg
                $ sudo apt install yamlmode (NOT NEEDED)
                in the file Agent/tpm/tpm_main.py ho cambiato l'import di json)
        )


You need to open the keylime.conf file and configure the agent by modifing the field for the ip of the tenant, registrar and verifier.
Once you have changed the proper fields in the keylime.conf file in the agent, you should configure also the keylime.conf file in the verifier/tenant/registrar node, at /etc/keylime.conf.

Once the configuration is properly set, we can lunch the program.
The agent should be run only after the verifier node is up, so the order in which the programs should be run is:
                (on the verifier node)
                $ sudo keylime_verifier &
                $ sudo keylime_registrar &
                

                (on the trust agent, in the directory Trust_agent/Agent)
                $ sudo python3 ./agent.py

                (on the verifier again)
                $ sudo keylime_tenant -c <uuid_agent> -t <ip_agent> -f <file_to_send_encrypted> 