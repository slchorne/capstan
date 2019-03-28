# NAME

capstan : an implementation of RFC 5011 for Infoblox

# SYNOPSIS

     ./capstan.pl

     ./capstan.pl --init --gm my.grid.master --user admin

     ./capstan.pl -a org 
     ./capstan.pl -a org -v internal
     ./capstan.pl -a org -m ns1.myco.com

    Options:

     -a <domain>   Add a domain to track
     -r <domain>   Remove a domain to track
     -v <view>     Add/Remove a domain from this view
     -m <member>   Add/Remove a domain from this member
     -l            List tracked domains
     -k            List tracked keys

     -ns <name>    Set the query nameserver to this member

     -help      Show a brief help message
     -C         Show the current configuration
     -c         Show just the local configuration

     --init         Initialise the system (only runs once)
                    requires --gm and --user
       --gm <name>  Set the Grid Master
       --user       Set the username (and password) for login

# DESCRIPTION

# OPTIONS

## -a &lt;domain>

Add a domain to the tracker, primed by an initial trust anchor(s)

This will look in the existing trust anchor in the Grid, View or Member
DNS properties, and, if it finds one, use this to prime a lookup for the
published trust anchors for that domain.

All the published keys will then be tracked for that domain.

You only need a single key to be added to the DNS settings to prime the
domain

This will create a TXT record(s) in the rfc5011.local zone for the namespace
of the tracked domain

## -r &lt;domain>

Remove a domain to the tracker

This will remove the matching TXT record in the rfc5011.local zone for
the namespace of the tracked domain

## -l 

List all the domains being tracked

This will get all the TXT records in the rfc5011.local zone where the
extensible\_attribute 'RFC5011Type' == 'domain'

## -k 

List all the trust anchors being tracked

This will get all the TXT records in the rfc5011.local zone where the
extensible\_attribute 'RFC5011Type' == 'key' and show what domain and area
of the grid they relate to

## -m &lt;grid.nameserver>

Set the grid member to be used for DNS queries.

Thus must be a grid member, and needs to be able to make recursive
queries for the domains being managed by this utility.

## --gm &lt;grid.master>

Set or change the GM address/name that the system manages.

This is usually done as part of the '--init' process, but may nttd to be
updated as part of a grid re-configuration (E.g DR)

## --user &lt;username>

Set or change the username (and password) configured to make API calls to
the grid.

You will be prompted to enter the password

## -c 

Show just the local configuration settings ( grid master, username , etc )

## -C 

Show the complete configuration settings, including all tracked domains
and keys

## --init

Initialise the system and configure all required settings.
You should only ever need to do this once

    ./capstan.pl --init --gm my.grid.master --user admin

This requires you to specify the grid master, and you will be prompted for
a password for the user account. The use must be enabled for API access
and be able to modify DNS zones, records, Grid DNS settings, Grid memners
and extensible\_attributes FORCE

The init process will :

    - create any required extensible_attributes
    - create the zone 'rfc5011.Infoblox.local' 
    - set up any other required configuration

# DATA STORAGE

The IETF has a number of drafts (and RFCs) relating to the storage and
management of trust anchors, while at the same time acknowleging the
conflicts that may occur when applying these rules to RFC5011.

This is further compounded by the way trust anchors are stored on the
infoblox grid, and that RFC5011 requires you to track DNSKEYS
that are not in the published RRSET for a domain.

This utility follows the basic principle of all those recomendations in
that the management system should not rely on the keys in its database but
merely use them to prime queries for records in the DNS.

It should also be noted tht while DNSKEY RRs and RRSIG rrs can be related
via the 'keytag', this tag will change if a key is revoked, so that method
can't be used to track a key through it's lifecycle. The DS signature
can't be used for simliar reasons. (see the section on 'KEYTAGS')

As such, the system uses the following components to track a trust
anchor through its life cycle:

- Untracked trust anchors

    Untracked Trust anchors are added manually to the Grid,view, or member
    DNSSEC settings. This is how you bootstrap a domain

- Valid trust anchors

    Valid trust anchors are automatically added and removed to the Grid,view,
    or member DNSSEC settings

    The algorithm field in the Infoblox settings uses a different format to
    the one described in any of the RFCs or in the Net::DNS::Sec libraries. A
    lookup table is used to convert between the formats

- rfc5011.infoblox.local zone

    The utility tracks all other configuration in the disabled dns zone
    'rfc5011.infoblox.local'. This zone shoud only ever contain TXT records.
    And modifying it by hand will obviously cause some issues

- Tracked domains

    Tracked domains are added as TXT records to the 'rfc5011.infoblox.local'
    zone. The records are added in the form

        DOMAIN.NAME.LEVEL.rfc5011.infoblox.local

    e.g:

        org.default.grid.rfc5011.infoblox.local IN TXT
        org.ns1.company.member.rfc5011.infoblox.local IN TXT
        org.internal.view.rfc5011.infoblox.local IN TXT

- Tracked keys

    Tracked keys are added as TXT records to the 'rfc5011.infoblox.local'
    zone. The records are added in the form

        GRIDID.key.DOMAIN.NAME.LEVEL.rfc5011.infoblox.local

    The state and timers and other information are stored in
    extensible\_attributes on the record.

    e.g:

        9795.key.org.default.grid.rfc5011.infoblox.local IN TXT
        21366.key.org.ns1.company.member.rfc5011.infoblox.local IN TXT
        9795.key.org.internal.view.rfc5011.infoblox.local IN TXT

    The GRIDID is not the keytag for the record, as this could change if a
    key is revoked or similar. Instead it is a variation of the keytag that
    ignores any flags that are set on the RR.  As such, the DNSKEY keytag
    can't be directly used to match a queried RR to one in the config.  ( see
    the section on KEYTAGS )

    The KEY is not stored on the record, just the ID that is then used to
    find a matching record from a valid current DNS query.

# KEYTAGS

Why do I see 2 different keytags or ids for a DNSKEY ?

The keytag algorithm is calculated from both the key and the flags in the
DNSKEY record.  While this tag can be used to match a key to it's
signature, if you REVOKE a key you change the flags, and thus the tag.  So
it is no longer possible to use the tag to compare a revoked key to its
unrevoked version.

This tool calculates a new, different, tag that ignores all the flags and
just calculates the value from the key itself.  The logging reports both
tags so you can compare resulds from DNS queries to results calculated
internally by this tool.

The algorithm used is a variation of the one defined in RFC4034 Appendix
B, with the 'flags','protocol' and 'algorithm' are all set to 0.

# DIAGNOSTICS

Use '-d N' to run at different diagnostic/debug levels

The higher the number, the more feedback you get

## Messages

Messages are logged with either an 'INFO' , 'WARN' or 'ERROR' header:

- `ERROR : The record '8763.key....' already exists`

    You are trying to add or track a domain that is already in the tracking
    system.  This is mostly benign, but the state of that key will be
    incorrect until the system runs again and re-validates all the keys.

    \[Description of error here\]

- `Another error message here`

    \[Description of error here\]

    \[Et cetera, et cetera\]

# DEPENDENCIES

    Storable
    Net::DNS, Net::DNS::Sec
    Infoblox.pm
    Digest::MD5

# INCOMPATIBILITIES

Not all algorithms are supported, as a manual lookup table is required to
convert beteen public and Infoblox supported algorithms

Unicode may be a problem, dependong on the domain name being added as
SEP.

I have not yet thought through other incompatibilities, though there are
most certainly some. I don't like code that is longer than 72 characters
per line, you may hate me for that.

# BUGS 

No bugs have been reported. Yet.

# SEE ALSO

    perldoc, perlfunc

# AUTHOR

Copyright (c) 2015, Geoff Horne, SLC . All rights reserved.
