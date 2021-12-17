# pulp_centos_errata_import
Imports CentOS (from http://cefs.steve-meier.de/) errata into pulp

This script imports CentOS Errata into Katello 4.x via Pulp 3.
It relies on preformatted information since parsing email
is the road to madness...

To run this script on CentOS you need:
 - perl-XML-Simple
 - perl-XML-Parser
 - perl-Text-Unidecode 
 - perl-REST-Client
 - perl-JSON
 - perl-HTTP-Message

This script was modified from Steve Meier's script for spacewalk  
which can be found at http://cefs.steve-meier.de/

# Usage
  1. Sync repositories
  2. See [Authentication](#Authentication) Below
  3. Run the script  
     wget -N http://cefs.steve-meier.de/errata.latest.xml
     ./errata_import.pl --errata=errata.latest.xml --host=foreman.example.com
  4. Go to "Administer" > "Settings" > "Katello" and set "force_post_sync_action" to true. (Katello 3.0 and up)
  5. Sync repositories so that errata is published. (The errata will not show up on the Katello/Foreman interface until this step is completed. )

# Authentication

We must authenticate to pulp.  This authentication information can be provided to pulp-admin in the following way:

User certificates (~/.pulp/cert.pem and ~/.pulp/priv.pem) If you are using this
script with katello, the foreman-installer creates a certificate suitable for
use with pulp.  You can use the cert by doing the following:

```shell
cp /etc/pki/katello/certs/pulp-client.crt ~/.pulp/cert.pem
cp /etc/pki/katello/private/pulp-client.key ~/.pulp/priv.pem
chmod 400 ~/.pulp/*.pem
```

# Parameters 

[Required]  
   --errata    - Path to the errata XML file.  
   --host      - Host name of your smart proxy

[Optional]  
   --rhsa-oval     - Path to the OVAL XML file from Red Hat (recommended)  
   --include-repo  - Only consider packages and errata in the provided repositories. Can be provided multiple times.  

[Logging]  
   --quiet         - Only print warnings and errors  
   --debug         - Set verbosity to debug (use this when reporting issues!)  

# Warning

- I offer no guarantees that this script will work for you.
  It is offered as is!
- this script will probably look horrific to anyone not familiar with the PERL language.

# Contributing

Please feel free to make pull requests for any
issues or errors in the script you may find.

