#!/usr/bin/env perl
#
# Perl common chunks
#
use strict ;
use feature qw(say switch);
use Storable qw( retrieve lock_store );
use Term::ReadKey;
use Digest::MD5 qw(md5_base64);

use Data::Dumper;
$Data::Dumper::Sortkeys = 1 ;

# SSL/LWP checks?
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;

#### work out where i am
# these variables can then be used to find config files
# and keep the code portable

use FindBin qw($Bin $Script);
my ($BASE,$NAME)=($Bin,$Script) ;
( my $SCRIPTNAME = $NAME ) =~ s/\.pl//;

use lib "lib" ;
use lib "$FindBin::Bin" ;
use lib "$FindBin::Bin/lib" ;

use Infoblox;
use Net::DNS;

# auto include help|?' => pod2usage(2)
use Getopt::Long qw(:config no_ignore_case auto_help);
use Pod::Usage;

# source Net-DNS-SEC/RR/DNSKEY.pm

my @ALGBYNUM = (
        1=>"RSAMD5",
        3=>"DSA",
        5=>"RSASHA1",
        6=>"NSEC3DSA",
        7=>"NSEC3RSASHA1",
        8=>"RSASHA256",
        10=>"RSASHA512",
#         11=>""   # reserver
        12=>"ECCGOST",
        13=>"ECDSAP256SHA256",
        14=>"ECDSAP384SHA384",
);

my %ALGNUMLOOK = @ALGBYNUM ;
my %ALGLOOK = reverse @ALGBYNUM ;

my $GRIDMASTER ;
my $NAMESERVER ;
my $USER ;
my $PASS ;

my $INIT ;
my $SHOWCONFIG ;
my $SHOWLOCALCONFIG ;

my $ADD;
my $REMOVE;
my $LISTDOMAINS;
my $LISTKEYS;
my $TESTKEYS;
my $PASSIVE;
my $MEMBER ;
my $VIEW ;

my $KEYLEVEL = 'grid';
my $KEYNAME = 'default';

my $DEBUG ;
my $NOOP ;
my $FORCE ;
my $TESTSTATE ; # just for testing
my $XRES ; # dummy test offline resolver

# DO NOT SET ANY OTHER GLOBALS, here or anywhere near here
# set the rest in the $conf{} in initConfig()

my $CONFFILE = "$BASE/$SCRIPTNAME.cfg";
my $AUTOCOMM = "Auto added by RFC5011 Capstan";

my $ores = GetOptions (
#     "V|version"    => sub { print "\n$ID\n$REV\n\n"; exit ; },
    "gm=s"      => \$GRIDMASTER,
    "m=s"       => \$MEMBER,
    "ns=s"       => \$NAMESERVER,
    "u|user=s"   => \$USER,
    "pass=s"     => \$PASS,

    "a=s"     => \$ADD,
    "r=s"     => \$REMOVE,
    "l"       => \$LISTDOMAINS,
    "k"       => \$LISTKEYS,
#     "s"       => \$RESYNC,
    "p"       => \$PASSIVE,
    "t"       => \$TESTKEYS,
    "v=s"     => \$VIEW,
    "m=s"     => \$MEMBER,

    "C"       => \$SHOWCONFIG,
    "c"       => \$SHOWLOCALCONFIG,
    "init"    => \$INIT,
    "f"       => \$FORCE,

    "d=s"     => \$DEBUG,
    "n"       => \$NOOP,      # GN;DN
    "x=s"     => \$XRES,      # local test hack
    "w=s"     => \$TESTSTATE, # local test hack
);

exit unless $ores;

#######################################

=head1 NAME

capstan : an implementation of RFC 5011 for Infoblox

=head1 SYNOPSIS

  ./capstan.pl

  ./capstan.pl --init --gm my.grid.master --user admin

  ./capstan.pl -a org 
  ./capstan.pl -a org -v internal
  ./capstan.pl -a org -m ns1.myco.com

 Options:

  -a <domain>   Add a domain to track
  -r <domain>   Remove a domain to track
  -l            List tracked domains
  -k            List tracked keys

  -help      Show a brief help message
  -C         Show the current configuration
  -c         Show just the local configuration
  --init     Initialise the system (only runs once)
             requires --gm and --user

  -ns <name>  Set the query nameserver to this member
  --user     Set the username (and password) for login

=head1 DESCRIPTION

=for author to fill in:
    Write a full description of the module and its features here.
    Use subsections (=head2, =head3) as appropriate.

=cut

########################################
# never die, let the script trap all errors

# first try and initialise
if ( $INIT ) {
    if ( $GRIDMASTER and $USER ) {
        initConfig( $GRIDMASTER , $USER )
    }
    else {
        pod2usage(2);
    }
    exit ;
}

# load up the local config, the loaders kick errors
my $conf = loadLocalConfig() or exit;

# do some local config settings and exit early
setUser( $conf , $USER ) && exit if $USER ;
setMaster( $conf , $GRIDMASTER ) && exit if $GRIDMASTER ;
setMemberNS( $conf , $NAMESERVER ) && exit if $NAMESERVER ;

# now talk to the grid and get the systemwide configuration
# to add to the config
loadGridConf( $conf ) or exit;

showConfig( $conf ) && exit if $SHOWCONFIG ; 

# adding domains requires key validation, 
# and essentially everything that relates to the grid config
# so we may as well pull the whole config, coz we won't get any
# performance gain by bypassing this step (and we would just dupe a messy
# pile o' code)

if ( $VIEW ) {
    $KEYLEVEL='view';
    $KEYNAME=$VIEW;
}
if ( $MEMBER ) {
    $KEYLEVEL='member';
    $KEYNAME=$MEMBER;
}

addDomain( $conf , $KEYLEVEL, $KEYNAME, $ADD ) && exit if $ADD;
delDomain( $conf , $KEYLEVEL, $KEYNAME, $REMOVE ) && exit if $REMOVE;

# strictly speaking these on-offs could happen before
# calling loadGridConf(), but by doing them here, and just checking the
# config, we have slightly cleaner code
listDomains( $conf ) && exit if $LISTDOMAINS ;
listKeys( $conf ) && exit if $LISTKEYS ;

###
#
# Main statemachine :
#

checkAllKeys( $conf );

#
# lastly, we don't know what happened, so we kick a restart just for
# grins
#
restartServices( $conf ) ;

exit ;

########################################
# SUBS
########################################

=head1 OPTIONS

=head2 -a <domain>

Add a domain to the tracker, primed by an initial trust anchor(s)

This will look in the existing trust anchor in the Grid, View or Member
DNS properties, and, if it finds one, use this to prime a lookup for the
published trust anchors for that domain.

All the published keys will then be tracked for that domain.

You only need a single key to be added to the DNS settings to prime the
domain

This will create a TXT record(s) in the rfc5011.local zone for the namespace
of the tracked domain

=cut

#
# Add a domain to the tracker
#

sub addDomain {
    my ( $conf , $level , $lname , $domain ) = @_ ;

    # adding a domain requires using an existing trust anchor
    # so we just use the config to get the grid anchor, and prime a DNS query
    # we return any valid anchors for this domain as a list of IDs
    # and additonal keys we also found

    my $validIDs = validateDomainKeys( $conf , $level , $lname , $domain );

    return 1 unless $validIDs ;

    # we now have a list of valid keys, 
    # and a list of anchors

    # so normalise the keys to an index based on the id, not the tag
    # so we can match the keys even if they were revoked
    
    my $validKeyIDs = { map { $_->{rdata}->keyid => $_ }
            values %{ $validIDs } };

    # $validKeyIDs is now a HASHREF with the state for each GRIDID
    # and the Net::DNS::RR::DNSKEY record
    # 9795 => {
    #   rdata => { Net::DNS::RR::DNSKEY }
    #   state => 'valid|revoked|...'
    # }

    # then we can directly compare these to what we have in the grid
    # this is really a subset of the statemachine...

    # first check the anchors for any bad keys

    my $anchors = $conf->{anchors}{$level}{$lname}{$domain} ;

    my $badanchors ;
    foreach my $id ( sort {$a <=> $b} keys %{ $anchors } ) {
        if ( $validKeyIDs->{$id} ) {
            if ( $validKeyIDs->{$id}->{state} =~ /revoked/i ) {
                logerror("Anchor $id was revoked for domain $domain");
                $badanchors++;
            }
        }
        else {
            logerror("Anchor $id is not a valid key for domain $domain");
            $badanchors++;
        }
#         print Dumper ( $validKeyIDs->{$id} );
    }
    return 1 if $badanchors ;

    # all our configured anchors are good, we can add this domain
    logit("all configured anchors are valid for domain $domain");

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # add the domain to be tracked to the zone
    logit( "Adding tracking domain $domain");

#     my $level = 'grid';
#     my $lname = 'default';

    my $fqdn = join ( "." , $domain , $lname , $level , $conf->{zone} );

    if ( $TESTKEYS ) {
        logwarn( "test mode : add domain $fqdn" );
    }
    else {

        my $tobj = Infoblox::DNS::Record::TXT->new(
            name => $fqdn,
            text => "domain:$domain loc:$level",
            comment => $AUTOCOMM,
            extensible_attributes => { 
                RFC5011Level => $level,
                RFC5011Name => $lname,
                RFC5011Type => 'domain' 
            },
        );
                
        $session->add( $tobj );
        getSessionErrors( $session , "domain $fqdn" );
    }

    #
    # All the keys are now a superset of the trust anchors,
    # so we walk the GID index of these keys and decide if they are
    # valid or pending
    #

    foreach my $id ( sort {$a <=> $b} keys %{ $validKeyIDs } ) {
        my $krec = $validKeyIDs->{$id};
        my $rr = $krec->{rdata};

        # generate a non-changing ID
        my $tag = $rr->keytag() ;

        my $rec = {
            domain => $domain,
            id => $tag,
            gid => $id,
            level => $level,
            lvlname => $lname,
            state => 'pending',
        };
        
        if ( $anchors->{$id} ) {
#         if ( grep ( /^$id$/ , @{ $anchorids } ) ) {
            $rec->{state} = 'valid',
        }

        addKey( $conf , $rec );

    }

    # we can also throw away the query data after this, because we will
    # do another query if we need to later.

    return 1 ;

}

=head2 -r <domain>

Remove a domain to the tracker

This will remove the matching TXT record in the rfc5011.local zone for
the namespace of the tracked domain

=cut

sub delDomain {
    my ( $conf , $level , $lname , $domain ) = @_ ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # remove the domain to be tracked
#     my $level = 'grid';
#     my $levelname = 'default';
    my $parent = join ( "." , $domain , $lname , $level , $conf->{zone} );


    logit( "Deleting tracking domain $domain");

    # now just remove anything under this namespace

    my ( @results ) = $session->search(
        object => "Infoblox::DNS::Record::TXT",
        name => $parent,
        zone => $conf->{zone},
#         extensible_attributes => { RFC5011Type => { value => "domain" } }
    );
    getSessionErrors( $session , "find domain $parent" );

    if ( @results ) {
        foreach my $rec ( @results ) {
            my $name = $rec->name();
            logit( "remove : $name" );

            $session->remove( $rec );
            getSessionErrors( $session , "delete rr $name" );
        }
    }

    return 1 ;

}

#
# add a key to the zone file for tracking
#
sub addKey {
    my ( $conf , $rec ) = @_ ;

    # we have to set some defaults of the PAII will choke on
    # invalid/blank EA values
    my $id = $rec->{id};
    my $gid = $rec->{gid};
    my $domain = $rec->{domain};
    my $level = $rec->{level} || 'grid' ;
    my $lvlname = $rec->{lvlname} || 'default' ;
    my $state = $rec->{state} || 'start' ;
    my $info = $rec->{info};

    # add the domain to be tracked
    my $fqdn = join ( "." , $gid , 'key' , $domain , $lvlname , 
                            $level , $conf->{zone} );

    # add the tracking zone
    logit( "Adding key $gid ($id) for $domain as $state");

    return if $TESTKEYS ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    my $tobj = Infoblox::DNS::Record::TXT->new(
        name => $fqdn,
        text => "domain:$domain tag:$id loc:$level",
        comment => $AUTOCOMM,
        extensible_attributes => { 
            RFC5011Time => time(),
            RFC5011State => $state,
            RFC5011Level => $level,
            RFC5011Name => $lvlname,
            RFC5011Type => 'key' 
        },
    );
            
    $session->add( $tobj );
    getSessionErrors( $session , "key $fqdn" );

    return 1 ;

}

#
# modify a key
#
sub updateKey {
    my ( $conf , $rec , $keyrr ) = @_ ;

    return if $TESTKEYS ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # add the domain to be tracked
    my $fqdn = join ( "." , $rec->{gid}, 'key',
        $rec->{domain},
        $rec->{lvlname},
        $rec->{level},
        $conf->{zone} );

    # add the tracking zone
    logit( "modify key : $rec->{gid} : $fqdn : $rec->{state}");

    my ( $tobj ) = $session->get(
        object => "Infoblox::DNS::Record::TXT",
        name => $fqdn,
#         zone => $conf->{zone},
#         extensible_attributes => { RFC5011Type => { value => "key" } }
    );
    getSessionErrors( $session , "modify key" ) if $DEBUG ;

    return unless $tobj ;

    # only change the TXT if we have valid data
    if ( $keyrr ) {
        my $tag = $keyrr->keytag();
        $tobj->text( "domain:$rec->{domain} tag:$tag loc:$rec->{level}" );
    }
    my $exts = $tobj->extensible_attributes();
    $exts->{RFC5011Time} = time() ;
    $exts->{RFC5011State} = $rec->{state} ;
    $tobj->extensible_attributes( $exts );

    $session->modify( $tobj );
    getSessionErrors( $session ); 

    return 1 ;

}

#
# delete a key
#
sub removeKey {
    my ( $conf , $rec ) = @_ ;

    return if $TESTKEYS ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # add the domain to be tracked
    my $fqdn = join ( "." , $rec->{gid}, 'key',
        $rec->{domain},
        $rec->{lvlname},
        $rec->{level},
        $conf->{zone} );

    # add the tracking zone
    logit( "remove key : $rec->{gid} : $fqdn : $rec->{state}");

    my ( $tobj ) = $session->get(
        object => "Infoblox::DNS::Record::TXT",
        name => $fqdn,
#         zone => $conf->{zone},
#         extensible_attributes => { RFC5011Type => { value => "key" } }
    );
    getSessionErrors( $session , "remove key" ) if $DEBUG ;

    return unless $tobj ;

    $session->remove( $tobj );
    getSessionErrors( $session ); 

    return 1 ;

}

#
# add a key to the grid properties
#
# Requires a domain, and a Net::DNS::RR::DNSKEY record
#

# You can only ever publish keys that were already in the system
# so all you should need is the config, and a ref to the record
# the rest we can pull from the record
# 
sub publishKey {
    my ( $conf , $level, $lname, $domain , $keyrr ) = @_ ;

    return if $TESTKEYS ;

    my $id = $keyrr->keyid();

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    logit( "Trusting key $id for $domain");

    #
    # avoid race conditions with the config, and 
    # just call getAnchors(); ( but we don't use the $anchors hash )
#     my ( $anchors , $gobj ) = getAnchors( $conf );
    my ( $gobj ) = getDNSSettings( $conf , $level, $lname );

    return undef unless $gobj ;

    my $gridkeys = $gobj->dnssec_trusted_keys();

    print Dumper ( (caller(0))[3] , $keyrr ) if $DEBUG ;

    # create and add the key object
    # [ ] hope that it isn't already there...

    my $keydef = Infoblox::DNS::DnssecTrustedKey->new(
           fqdn => $domain,
           algorithm => getAlgorithm( $keyrr->algorithm() ),
#            algorithm => $rdata->{algorithm},
           key => $keyrr->key(),
    );
    getApiErrors() unless $keydef ;

    push @{ $gridkeys } , $keydef ;

    # update and modify
    $gobj->dnssec_trusted_keys( $gridkeys );

    $session->modify( $gobj );
    getSessionErrors( $session , "publishKey : modify Infoblox::Grid::DNS"); 

    return 1 ;

}

#
# remove a key to the grid properties
#   disco(ontinue)Key
#
# we can pass either a kerRR or an ID for a key,
# Either will work
# 
sub discoKey {
    my ( $conf , $level, $lname, $domain , $keyrr , $id ) = @_ ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # this new key could be a revoked version of the key we
    # were trusting. So to compare it we use the GID, not the tag
    # ( as the tag changes when you revoke a key );

    $id = $keyrr->keyid() unless $id ;

    logit( "UnTrusting key $id for $domain");

    print Dumper ( (caller(0))[3] , $keyrr ) if $DEBUG ;

    #
    # [ ] this is ugly that we get ALL the keys,
    # We should just get keys for this level/name
    #
    # we can't use the anchors already in the config, 
    # we may have done things in a previous loop and that altered the
    # config. So we have to refresh the data direct from the grid

    # So just pull them again from the grid
    # these are indexed by domain and GID, ( to avoid conflicts )
    #     'com' => {
    #       '30909' => {
    #     'org' => {
    #       '21366' => ...

    my $allanchors = getAnchors( $conf );
    my $gobj = getDNSSettings( $conf , $level , $lname );

    # now just walk this index, and remove the key we want

    my $newkeys = [];
    my $anchors = $allanchors->{$level}{$lname};

    print Dumper ( (caller(0))[3] , $anchors ) if $DEBUG ;

    # all the keys for DNS settings are in a single list,
    # regardless of domain, so we have to walk all of them and match
    # them to the config

    foreach my $dom ( keys %{ $anchors } ) {
        foreach my $atag ( keys %{ $anchors->{$dom} } ) {
            if ( $dom eq $domain && $atag == $id ) {
                logit( "Removing $domain $id" );
            }
            else {
                push @{ $newkeys } , $anchors->{$dom}{$atag} ;
            }
        }
    }

    return if $TESTKEYS ;

    $gobj->dnssec_trusted_keys( $newkeys );

    $session->modify( $gobj );
    getSessionErrors( $session , "discokey : modify Infoblox::Grid::DNS"); 

    return 1 ;

}

=head2 -l 

List all the domains being tracked

This will get all the TXT records in the rfc5011.local zone where the
extensible_attribute 'RFC5011Type' == 'domain'

=cut

#
# format domain data from the conf
#

sub listDomains {
    my ( $conf ) = @_ ;

    # it's a struct, so use dumper
    local $Data::Dumper::Terse = 1 ;
    print Dumper ( $conf->{domains} );

#     if ( $conf->{domains} ) {
#         print join ( "\n" , @{ $conf->{domains} } ) ."\n";
#     }

    return 1
}

=head2 -k 

List all the trust anchors being tracked

This will get all the TXT records in the rfc5011.local zone where the
extensible_attribute 'RFC5011Type' == 'key' and show what domain and area
of the grid they relate to

=cut

#
# format key data from the conf
#
sub listKeys {

    local $Data::Dumper::Terse = 1 ;
#     local $Data::Dumper::Maxdepth = 4 ;
    print Dumper ( $conf->{keys} );

    # we want a better formatter than data::dumper
    # in theory we could do this at load time, but the sorting may suck
    # really, we want recursion here and be ignorant of the struct
    # but that turns out to be more lines of code...

#     print "\n";
#     foreach my $area ( sort keys %{ $conf->{keys} } ) {
#         foreach my $loc ( sort keys %{ $conf->{keys}{$area} } ) {
#             foreach my $domain ( sort keys %{ $conf->{keys}{$area}{$loc} } ) {
#                 my $drec = $conf->{keys}{$area}{$loc}{$domain};
#                 foreach my $id ( sort keys %{ $drec } ) {
#                     print "$area : $loc : $domain : $id\n";
#                 }
#             }
#         }
#     }
#     print "\n";

    return 1;
}

######################################################
#
# DNS queries and resolver stuff handling
# Net::DNS operations
#

sub getResolver {
    my ( $conf ) = @_ ;

    return undef unless $conf->{nameserver};

    # uses fancy ref caching..
    return $conf->{resolver} if $conf->{resolver} ;

    # and local hacks
    my $ns = $XRES ? $XRES : $conf->{nameserver};

    logit ( "Sending DNS queries to $ns");

    my $res = Net::DNS::Resolver->new;
    $res->nameservers( $ns );
    $res->tcp_timeout(10);
    $res->udp_timeout(5);

    # and cache it
    $conf->{resolver} = $res ;

    return ( $res ) ;
}

#
# Generic DNS loopup operations
# DNS lookup with error checking, returns Net::DNS::Packet" object
#

sub querybyType {
    my ( $conf , $fqdn , $type ) = @_ ;
    my $resolver = getResolver( $conf );

    logit( "query : $fqdn : for $type");
    # get ALL the DNSKEYS for this domain
    my $rrs = $resolver->send($fqdn , $type, "IN");

#     say $resolver->errorstring;
#     say $rrs->answer;

    # $query is a a "Net::DNS::Packet" object, ALWAYS returned
    # Check if ->answer is undef for errors
    if ( ! $rrs->answer ) {
        # we got an error
        logerror( "$type query : $fqdn : " . $resolver->errorstring );
    }
    return $rrs ;
}


#
# get all keys for a domain, index by ID
#
# return the and index of SEP keys, and all the keys
#

sub queryAndIndexKeys {
    my ( $conf , $domain ) = @_ ;
    my $keys = querybyType( $conf , $domain , 'DNSKEY' );

    # now index these keys by their keyid, but only keep SEP keys
    my $keyindex ;
    foreach my $krr ($keys->answer) {
        next unless $krr->sep();
#         $keyindex->{ $krr->keyid() } = $krr;
        $keyindex->{ $krr->keytag() } = $krr;
    }

    return ( $keyindex , $keys->answer );
}

#
# get all signatures for a domain, index by ID
#
# return the index
#

sub queryAndIndexSigs {
    my ( $conf , $domain ) = @_ ;

    my $sigs = querybyType( $conf , $domain , 'RRSIG' );

    my $sigindex ;
    # now find the right SIGs for our project and put them in an index
    foreach my $rr ($sigs->answer) {
        next unless $rr->typecovered() eq 'DNSKEY';
        $sigindex->{ $rr->keytag() } = $rr ;
    }

    return $sigindex ;

}

#
# validate all keys in a domain.
# 
# validation requires you to get and compare ALL the keys, so you may as
# well do it in a batch and find a way to pass back bulk results
#
# you SHOULD ONLY validate from your existing keys, NOT from anything
# passed in the current RRset.
#
# So we have an odd kind of loop here, but it should work like this:
# - get the existing anchors,
# - find their signatures
# - check that these anchors still validate the keyset
# - check for revoked keys (arrg)
# - check for any new keys that are in the RRSET
#

sub validateDomainKeys {
    my ( $conf , $level, $lname , $domain ) = @_ ;

    # [ ] we need to know view/member context as well

    logit("validate : $level : $lname : $domain : in DNS");

    # now get all the keys from the trust anchors These will be
    # indexed by the GID
    my $anchors = $conf->{anchors}{$level}{$lname}{$domain} ;
    unless ( $anchors ) {
        logerror("validate : no active trust anchors in NIOS for $domain");
        return undef ;
    }

    # get the keys from dns
    my ( $idx, @allkeys ) = queryAndIndexKeys( $conf , $domain );
    return undef unless @allkeys ;

    # get all the signatures, indexed by keytag from DNS
    # we use the KEYTAG so we can match them to the DNS keys
    my $sigindex = queryAndIndexSigs( $conf , $domain );
    return undef unless $sigindex ;

    # we need at least 1 trust anchor to vaidate the keyset,
    # And we need a list of valid keys.
    # so track 2 states : Trusted : Valid 
    my $keystate = {};
    my @trustedKeySet ;
    my $faker = 1 ;   # loop hook for testing

    # now walk ALL of the DNS keys, and verify them
    foreach my $keyrr ( @allkeys ) {

        # only track trust anchors
        next unless $keyrr->sep();

        # keep all the dnsinfo, track an initial state
        my $tag = $keyrr->keytag();
        my $id = $keyrr->keyid();
        my $rrid = "$id tag[$tag]";
        my $krec = {
            rdata => $keyrr,
            state => undef ,
        };

        # assume all keys are bad
        my $vstate = 'invalid' ;
        my $tstate = 'untrusted' ;

        if ( $anchors->{$id} ) {
            $tstate = 'trusted' ;
        }

        # find the signature for this key
        my $sigrr = $sigindex->{ $tag };
        if ( ! $sigrr ) {
            logit( "key : $rrid : $tstate : $vstate : no RRSIG found" );
            $krec->{state} = 'nosig';
        }

        # --------------------------------------
        # hook for testing
        # fake an invalid key
        elsif ( $faker && $TESTSTATE =~ /invalid/i ) {
            # invalidate the first RR
            $krec->{state} = 'error';
            logwarn( "TEST : invalid key $tag");
            logerror( "key : $rrid : $tstate : $vstate" );
        }
        # --------------------------------------

        # now try and verify this signature, WRT a trust anchor
        # even revoked keys are valid in this context
        #
        # and even if we had a valid key in the past, if someone changes
        # the RRset and doesn't fix the signatures, it is possible
        # for a valid key to fail validation

        elsif ( $sigrr->verify( \@allkeys , $keyrr ) ) {
            $vstate = 'valid';
            # is this valid key trustworthy ?
            push @trustedKeySet , $id if $tstate eq 'trusted';
#             $trustedKeySet = 1 if $tstate eq 'trusted';

            $krec->{state} = 'valid';
            logit( "key : $rrid : $tstate : $vstate" );

            # revoked keys must still validate!!
            if ( $keyrr->revoke() ) {
                logit( "key : $rrid : $tstate : $vstate : revoked" );
                $krec->{state} = 'revoked';
            }
        }
        else {
            $krec->{state} = 'error';
            logerror( "key : $rrid : $tstate : $vstate : " . $sigrr->vrfyerrstr ) ;
        }

        # valid keys we keep, anything else we drop from the
        # validated DNSKEY RRSet
        if ( $vstate eq 'valid' ) {
            $keystate->{$tag} = $krec ;
        };

        # only fake the first rr in the set
        $faker = 0 ;
    }

    # now, for testing, we may inject or remove some keys
    # This is kinda hardcoded for now
    if ( $TESTSTATE ) {
        $keystate = setFakeKeys( $TESTSTATE , $keystate )
    }

    # and only return a trustworthy set
    #
    unless ( @trustedKeySet ) {
        logerror( "No trustworthy keys could be found" );
        return undef ;
    }

    return $keystate ;

}

######################################################
#
# Main operational routines
#

sub checkAllKeys {
    my ( $conf ) = @_ ;
    my $resolver = getResolver( $conf );

    # we have a bunch of nested loops here beaauce
    # we're supporting lots of config levels

    unless ( $conf->{domains} ) {
        logwarn( "No domains currently being tracked");
        return ;
    }

    foreach my $level ( sort keys %{ $conf->{domains} } ) {    
        foreach my $lname ( sort keys %{ $conf->{domains}{$level} } ) {    
            foreach my $domain ( @{ $conf->{domains}{$level}{$lname} } ) {
                logit( "--------------------" );
                logit( "process keys : $level : $lname : $domain" );

# Step 1 , 
#    Query DNS for the current valid trust anchors and their state

                # punt a domain to DNS, get back the state of all ids
                my $validIDs = validateDomainKeys( $conf , 
                    $level, $lname ,$domain );

                # if there was a DNS error, we don't return anything
                next unless $validIDs ;

# Step 2 , 
#   compare all keys on the grid to all keys in DNS,
#   and update the state of anything that changes

#                 print Dumper ( $validIDs );

                checkState ( $conf , {
                    level => $level,
                    lvlname => $lname,
                    domain => $domain,
                    keys => $validIDs,
                });

            }
        }
    }

    return ;

}

#
# compare the state of a set of key IDs with what we have in our config
#

sub checkState {
    my ( $conf , $args ) = @_ ;

    print Dumper ( (caller(0))[3] , $args ) if $DEBUG ;

    my $domain = $args->{domain};
    my $level = $args->{level};
    my $lname = $args->{lvlname};

    if ( $TESTKEYS ) {
        logwarn( "test mode : no config changes will be made" );
    }

# the statemachine
#
# Add Hold down time == 30 days ( 2592000 seconds )
# Remove Hold down time == 30 days 
#
# Any new 'Valid' keys can be published
# Any new 'Revoked' keys can be discoed
# anything else is just a flag in the database
# 
#     The key has not or ever been seen
# Start -> AddPend : if valid DNSKEY in RRSet with a new SEP key
# 
#     Wait until publishing
# AddPend -> Start : if key in not in valid DNSKEY RRSet
#         -> Valid : if key is in a valid RRSet after the 'add time'
#                    and it is still valid in the rrset
# 
#     You can publish this key
# Valid -> Missing : if key in not in valid DNSKEY RRSet
#       -> Revoked : if key has "REVOKED" bit set
# 
#     The key went missing without being revoked (abnormal state)
#     Continue to publish this key
# Missing -> Valid : if key is in valid DNSKEY RRSet
#         -> Revoked : if key has "REVOKED" bit set 
# 
#     DO NOT publish this key
# Revoked -> Removed : if revoked key is not in RRSet for 30 days
# 
#     DO NOT publish this key, and never re-publish this key
#     remove it from the database 30 days after it was 'removed'
#   Removed -> /dev/null
# And a removed key is no-longer of concern

    my $gdata = $conf->{keys}{$level}{$lname}{$domain};

#  $gdata looks like this:
#
#   'keys' => {
#     'grid' => {
#       'default' => {
#         'org' => {
#           '20334' => {
#             'domain' => 'org',
#             'gid' => '20334',
#             'level' => 'grid',
#             'lvlname' => 'default',
#             'state' => 'pending',
#             'time' => '1430091852'
#           },
#           '8763' => {
#             'domain' => 'org',
#             'gid' => '8763',
#             'level' => 'grid',
#             'lvlname' => 'default',
#             'state' => 'valid',
#             'time' => '1430091852'
#           }
#         }
#       }


    # a keytag could have changed if it was revoked, so we have to
    # create a new index of the Queried keys based on their 'keyid'

    my $validKeyIDs = { map { $_->{rdata}->keyid => $_ } 
            values %{ $args->{keys} } };

    # $validKeyIDs is now a HASHREF with the state for each GRIDID
    # and the Net::DNS::RR::DNSKEY record

#     GRIDID => {
#         state => STR
#         rdata => { Net::DNS::RR::DNSKEY },
#     }

    # check for any unknown anchors that we weren't tracking
    # and aren't new
    # someone may have added something to the gui,

    my $anchors = $conf->{anchors}{$level}{$lname}{$domain} ;
    foreach my $id ( sort {$a <=> $b} keys %{ $anchors } ) {
        unless ( $gdata->{$id} or $validKeyIDs->{$id} ) {
            logerror( "state : $id : anchor is unknown -> delete");
            discoKey( $conf , $level , $lname,
                $domain , undef , $id );
        }
    }

    # walk the keys we know about (on the grid)
    # since this is the last KNOWN state
    # and compare them to the keys we just queried


    foreach my $id ( sort {$a <=> $b} keys %{ $gdata } ) {

        my $grec = $gdata->{$id};
        my $gstate = $grec->{state};

        # be careful here, or we create an rr record we don't want
        my $krec;
        my $kstate;
        my $tag = '000' ;
        if ( $validKeyIDs->{$id} ) {
            $krec = $validKeyIDs->{$id};
            $kstate = $krec->{state};
            $tag = $krec->{rdata}->keytag();

#             print Dumper ( $krec ) ;
        }

        my $rrid = "$id tag[$tag]";


        # N: we are always comparing:
        #     LAST KNOWN STATE <=> Current state

        # cache some expire timers
        my $addendtime = $grec->{time} + $conf->{holdaddtime};
        my $remendtime = $grec->{time} + $conf->{holdremtime};

        # ignore things that don't change
        if ( $gstate eq $kstate ) {
            logit( "state : $rrid : no change");
        }

        # check pending keys
        elsif ( $gstate eq 'pending' ) {

            unless ( $krec ) {
                # the key went away, do nothing unless we are out of time
                if ( time() > $addendtime ) {
                    logit( "state : $rrid : pending -> delete");
                    removeKey( $conf , $grec );
                }

                # [ ] the RFC states we should re-set the timer
                # for this key, but that means the key will NEVER get
                # removed from the grid. IFF we see it again, it will get
                # added as pending, the the timer will get re-set at that
                # time

                next;
            }

            if ( $kstate eq 'valid' ) {
                # release from the timers
                if ( time() > $addendtime ) {
                    logit( "state : $rrid : pending -> valid : offhold");
                    $grec->{state} = 'valid';

                    print Dumper ( $grec ) if $DEBUG > 1 ;
#                     print Dumper ( $grec );

                    updateKey( $conf , $grec , $krec->{rdata} );
                    publishKey( $conf , $level , $lname ,
                        $domain , $krec->{rdata} );

                }
                else {
                    # it's valid but not ready yet
                    logit( "state : $rrid : pending -> onhold");
                }
            }
            else {
                # we should never get here
                logerror( "state : $rrid : unknown pending -> $kstate");
            }

        }

        # [ ] missing
        elsif ( $gstate eq 'missing' ) {
            unless ( $krec ) {
                # it's still missing ???
                my $mtime = time() - $grec->{time};
#                 logwarn( "state : $rrid : missing -> missing : revoke ?");
                logwarn( "state : $rrid : missing for $mtime secs : revoke ?");
                next ;

            }

            if ( $kstate eq 'valid' ) {
                # abnormal case, just track it
                logit( "state : $rrid : missing -> valid");
                $grec->{state} = 'valid';
                updateKey( $conf , $grec , $krec->{rdata} );
            }
            elsif ( $kstate eq 'revoked' ) {
                logit( "state : $rrid : missing -> revoked");

                # this is no longer a trust anchor
                $grec->{state} = 'revoked';
                updateKey( $conf , $grec , $krec->{rdata} );
                discoKey( $conf , $level, $lname,
                    $domain , $krec->{rdata} );
            }
            else {
                # we should never get here
                logerror( "state : $rrid : unknown missing -> $kstate");
            }
        }

        # [ ] Valid
        elsif ( $gstate eq 'valid' ) {

            unless ( $krec ) {
                # the key went away, without being revoked.
                # [ ] the RFC doesn't say what to do, just track it
                logwarn( "state : $rrid : valid -> missing");
#                 removeKey( $conf , $grec );
                $grec->{state} = 'missing';
                updateKey( $conf , $grec );
                next ;
            }

            if ( $kstate eq 'revoked' ) {
                logit( "state : $rrid : valid -> revoked");

                # this is no longer a trust anchor, and the keytag changed
                $grec->{id} = $krec->{rdata}->keytag(),
                $grec->{state} = 'revoked';
                updateKey( $conf , $grec , $krec->{rdata} );
                discoKey( $conf , $level, $lname,
                    $domain , $krec->{rdata} );
            }
            else {
                # we should never get here
                logerror( "state : $rrid : unknown valid -> $kstate");
            }

        }

        # [ ] Revoked
        elsif ( $gstate eq 'revoked' ) {
            if ( $kstate ) {
                # a revoked key became valid !!
                logerror( "state : $rrid : unknown revoked -> $kstate");
            }
            else {
                # the key was finally removed from the RRset
                logit( "state : $rrid : revoked -> removed");
                $grec->{state} = 'removed';
                updateKey( $conf , $grec );
            }
        }

        # [ ] Removed
        elsif ( $gstate eq 'removed' ) {
            if ( $kstate ) {
                # a removed key came back ??
                logerror( "state : $rrid : unknown removed -> $kstate");
            }
            else {
                # the key was finally removed from the RRset
                if ( time() > $remendtime ) {
                    logit( "state : $rrid : removed -> delete");
                    removeKey( $conf , $grec );
                }
            }
        }

        else {
            # if we get to here, we got an unknown condition
            logerror( "state : $rrid : unknown state : $gstate");
        }

        # FINALLY, remove this valid key from the list
        delete $validKeyIDs->{$id} if $validKeyIDs->{$id} ;

    }

    # then walk any dangling keys from the query
    # any remaining keys in the $validKeyIDs index are new to us
    # and should just be added as pending

    # [ ] corner case. we weren't tracking this key, but it is
    # both valid and already configured as a trust anchor,
    # iff so, the state should be valid... (but also applies to above)
    # - adds it as pending... and kicks an error, prob ok

    foreach my $id ( sort {$a <=> $b} keys %{ $validKeyIDs } ) {
    
        # send it to the pending queue
        # [ ] :
        logit( "newkey : $id : start -> pending");

        my $krec = $validKeyIDs->{$id};

        my $rec = {
            domain => $domain,
            level => $level,
            lvlname => $lname,
            id => $krec->{rdata}->keytag(),
            gid => $id,
            state => 'pending',
        };
        
        addKey( $conf , $rec );
        
    }

}

##################################################
#
# configuration handlers
# 

=head2 -m <grid.nameserver>

Set the grid member to be used for DNS queries.

Thus must be a grid member, and needs to be able to make recursive
queries for the domains being managed by this utility.

=cut

#
# set the grid ember for querying to,
# OR list All members if it wasn't found
# also remove the EA from any other member
#
sub setMemberNS {
    my ( $conf , $member ) = @_ ;

    my $session = startSession( $conf );  
    return 1 unless $session ;

    # search for all grid member objects
    my @members = $session->get(
        object => "Infoblox::Grid::Member",
#         name =>
#         extensible_attributes => { RFC5011Type => { value => "nameserver" } }
    );

    my $memberinfo ;
    my @cleanmembers ;
    my $newobj ;

    # first see if we even have a valid member to modify, if not
    # don't make any changes. So we check all the members and stage
    # the changes
    foreach my $mobj ( @members ) {
        my $name = $mobj->name();
        my $ip = $mobj->ipv4addr();

        my $state = getAttributes( $mobj , 'RFC5011Type' );

        # see if this member is the new query member
        if ( $name eq $member ) {
            logit( "setting $member as query nameserver" );
            $newobj = $mobj ;
        }
        # and track other members for cleanup
        elsif ( $state ) {
            push @cleanmembers , $mobj;
        }

        $memberinfo .= "  $name : $ip : $state\n";
    }

    # now make any necessary changes

    # if we found a new member to enable, disable all the others
    if ( $newobj ) {
        if ( @cleanmembers ) {
            foreach my $cobj ( @cleanmembers ) {
                setAttributes( $cobj , { RFC5011Type => '' } );
                $session->modify( $cobj );
                getSessionErrors( $session ); 
            }
        }

        # then (re) set this member
        setAttributes( $newobj , { RFC5011Type => 'nameserver' } );
        $session->modify( $newobj );
        getSessionErrors( $session ); 
    }
    else {
        logerror( "no member found by name : $member" );
        print "$memberinfo";
    }

    # must return TRUE
    return 1;

}

=head2 --gm <grid.master>

Set or change the GM address/name that the system manages.

This is usually done as part of the '--init' process, but may nttd to be
updated as part of a grid re-configuration (E.g DR)

=cut

#
# set the GM in the local config
#
sub setMaster {
    my ( $conf , $gm ) = @_ ;

    logit( "Changing Gridmaster to : $gm" );

    # re/set and save the GM to the local config
    $conf->{login}{master} = $gm ;

    saveLocalConfig( $conf );

    # must return OK
    return 1;
}

=head2 --user <username>

Set or change the username (and password) configured to make API calls to
the grid.

You will be prompted to enter the password

=cut

#
# get a password, save and write the config
#
sub setUser {
    my ( $conf , $user ) = @_ ;
    my $login = $conf->{login};

    logit( "Changing login user to : $user" );

    $login->{username} = $user ;

    # hack to bypass the prompt
    my $password = $PASS || undef ;

    unless ( $password ) {
        # just prompt for a username
        print "\nEnter password for user $user: ";
        ReadMode('noecho');
        chomp($password=<STDIN>);
        ReadMode('restore');

        print "\n";
    }

    $login->{password} = $password;

    saveLocalConfig( $conf );

    # return the config, just in case we needed it ?
    # must return OK
    return 1 ;
}

=head2 -c 

Show just the local configuration settings ( grid master, username , etc )

=cut

=head2 -C 

Show the complete configuration settings, including all tracked domains
and keys

=cut

#
# wrapper to hide some junk
#
sub showConfig {

    my ( $conf ) = @_ ;

    # move aside some values to hide them from display
    # but don't delete them...
    my $p = $conf->{login}{password};
    my $s = $conf->{session};

    $conf->{login}{password} = $conf->{login}{password} ? 'xxxxxxx' : undef ;
#     delete $conf->{login}{password};
    delete $conf->{session};
    print Dumper ( $conf ) ;

    # then put the saved values back
    $conf->{login}{password} = $p;
    $conf->{session} = $s;

}

=head2 --init

Initialise the system and configure all required settings.
You should only ever need to do this once

  ./capstan.pl --init --gm my.grid.master --user admin

This requires you to specify the grid master, and you will be prompted for
a password for the user account. The use must be enabled for API access
and be able to modify DNS zones, records, Grid DNS settings, Grid memners
and extensible_attributes FORCE

The init process will :

 - create any required extensible_attributes
 - create the zone 'rfc5011.Infoblox.local' 
 - set up any other required configuration

=cut

sub initConfig {
    my ( $server , $user ) = @_ ;

    logit ( "Initialising the config" );

    # check we haven't been here before
    if ( -f $CONFFILE && ! $FORCE ) {
        logerror( "There is already a running setup, exiting" );
        return ;
    }

    # create a blank config
    my $conf = {
        login => {
            master => $server,
            timeout => 5,
            username => "",
            password => "",
        },
        zone => "rfc5011.infoblox.local",
        holdaddtime => 2592000, # 30 days
        holdremtime => 2592000, # 30 days
    };

    # get a password for the username
    # ( or we can't talk to the grid and configure it);
    # and let setUser write the config to disk

    setUser( $conf , $user );

    logit( "Saving loginfo to disk");

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # Create some EAs
    foreach my $ea ( qw( 
                RFC5011Type
                RFC5011Time
                RFC5011State
                RFC5011Level
                RFC5011Name
        ) ) {
        logit( "Adding EA : $ea" );
        my ( $dobj ) = Infoblox::Grid::ExtensibleAttributeDef->new(
            name => $ea,
            type => "string",
        );
        $session->add( $dobj );
        getSessionErrors( $session ); 

    }

    # add the tracking zone
    logit( "Adding tracking zone $conf->{zone}");
    my $zobj = Infoblox::DNS::Zone->new(
        name => $conf->{zone},
        disable => 'true',
        comment => $AUTOCOMM,
    );
    $session->add( $zobj );
    getSessionErrors( $session , "zone $conf->{zone}" );

    return ;

}

sub loadGridConf {
    my ( $conf ) = @_ ;

    logit( "Loading  grid config..." );

    # we're passed the config from disk with the login info
    # so now append to it...

    # and we track any errors in the config, in case something got messed up
    my $conferrors ;

    my $session = startSession( $conf );  
    return unless $session ;

    # search for all grid member objects to find the namserver to use
    my ( $dnsmember ) = $session->get(
        object => "Infoblox::Grid::Member",
        extensible_attributes => { RFC5011Type => { value => "nameserver" } }
    );
    $conferrors++ if getSessionErrors( $session , "RFC5011 nameserver member" );

    # insert it into the main config
    if ( $dnsmember ) {
        $conf->{nameserver} = $dnsmember->ipv4addr();
        $conf->{member} = $dnsmember->name();
    }

    # find/check the zone we put all the records in...
    $conf->{zoneOK} = 'false' ;
    my ( $zobj ) = $session->get(
        object => "Infoblox::DNS::Zone",
        name => $conf->{zone},
    );
    $conferrors++ if getSessionErrors( $session , "zone $conf->{zone}" );

    $conf->{zoneOK} = 'true' ;

    # now get records from that zone, if we can
    if ( $zobj ) {
        $conf->{domains} = getDomains( $conf );
        $conf->{keys} = getKeys( $conf );
    }

    # and get any existing trust anchors
    $conf->{anchors} = getAnchors( $conf );

    print Dumper ( (caller(0))[3] ) if $DEBUG > 1 ;
    showConfig( $conf ) if $DEBUG > 1 ;

    if ( $conferrors ) {
        logerror ( "There are problems with the config, exiting" );
        return undef ;
    }

    return $conf ;

}

sub loadLocalConfig {

    logit( "Loading local config..." );

    my $data = undef ;
    # read from disk, this could DIE, so put it in an eval instead
    # also handle the initial case where the database is missing
    eval {
        $data = retrieve( $CONFFILE );
    };
    if ( $@ ) {
        print "$@\n" if $DEBUG;
        logerror( "There was a problem loading the config : $CONFFILE");
        logerror( "did you run '--init' first ?");
    }

    if ( $XRES ) {
        # developer hacks
        $data->{holdaddtime} = 20;
        $data->{holdremtime} = 20;
    }

    print Dumper ( $data ) if $DEBUG > 1 ;

    if ( $SHOWLOCALCONFIG ) {
        showConfig( $data );
        exit;
    }

    return $data ;

}

sub saveLocalConfig {
    my ( $conf ) = @_ ;
    lock_store $conf , $CONFFILE;
}

=head1 DATA STORAGE

The IETF has a number of drafts (and RFCs) relating to the storage and
management of trust anchors, while at the same time acknowleging the
conflicts that may occur when applying these rules to RFC5011.

This is further compounded by the way Trust anchors are stored on the
infoblox grid, and that RFC5011 requires you to track DNSKEYS
that are not in the published RRSET for a domain.

This utility follows the basic principle of all those recomendations in
that the management system should not rely on the keys in its database but
merely use them to prime queries for records in the DNS.

It should also be noted tht while DNSKEY RRs and RRSIG rrs can be related
via the 'keytag', this tag will change if a key is revoked, so that method
can't be used to track a key through it's lifecycle. The DS signature
can't be used for simliar reasons.

As such, the system uses the following components to track a trust
anchor through its life cycle:

=over

=item Untracked trust anchors

Untracked Trust anchors are added manually to the Grid,view, or member
DNSSEC settings. This is how you bootstrap a domain

=item Valid trust anchors

Valid trust anchors are automatically added and removed to the Grid,view,
or member DNSSEC settings

The algorithm field in the Infoblox settings uses a different format to
the one described in any of the RFCs or in the Net::DNS::Sec libraries. A
lookup table is used to convert between the formats

=item rfc5011.infoblox.local zone

The utility tracks all other configuration in the disabled dns zone
'rfc5011.infoblox.local'. This zone shoud only ever contain TXT records.
And modifying it by hand will obviously cause some issues

=item Tracked domains

Tracked domains are added as TXT records to the 'rfc5011.infoblox.local'
zone. The records are added in the form

    DOMAIN.NAME.LEVEL.rfc5011.infoblox.local

e.g:

    org.default.grid.rfc5011.infoblox.local IN TXT
    org.ns1.company.member.rfc5011.infoblox.local IN TXT
    org.internal.view.rfc5011.infoblox.local IN TXT

=item Tracked keys

Tracked keys are added as TXT records to the 'rfc5011.infoblox.local'
zone. The records are added in the form

    GRIDID.key.DOMAIN.NAME.LEVEL.rfc5011.infoblox.local

The state and timers and other information are stored in
extensible_attributes on the record.

e.g:

    9795.key.org.default.grid.rfc5011.infoblox.local IN TXT
    21366.key.org.ns1.company.member.rfc5011.infoblox.local IN TXT
    9795.key.org.internal.view.rfc5011.infoblox.local IN TXT

The GRIDID is not the keytag for the record, as this could change if a
key is revoked or similar. Instead it is a variation of the keytag that
ignores any flags that are set on the RR. As such it can't be directly
used to match a queried RR to one in the config. Instead you must
calculate the 'gridid' for the RR and match against that.

The algorithm used is a variation of the one defined in RFC4034 Appendix
B, with the 'flags','protocol' and 'algorithm' are all set to 0.

The KEY is not stored on the record, just the ID that is then used to
find a matching record from a valid current DNS query.

=back

=cut

#
# pull all the domains from the config zone
#
# ALL TXT records tagged as 'domain'
#

sub getDomains {
    my ( $conf ) = @_ ;

    # get all the domains and insert them into the config
    # called from loadGridConf

    my $domaindata ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    my ( @domains ) = $session->search(
        object => "Infoblox::DNS::Record::TXT",
        zone => $conf->{zone},
        extensible_attributes => { RFC5011Type => { value => "domain" } }
    );
    getSessionErrors( $session , "list domains" ) if $DEBUG ;

#     print Dumper ( \@domains );

    # we want a hierarichal struct

    if ( @domains ) {
        foreach my $dobj ( @domains ) {
            my $level = getAttributes( $dobj , 'RFC5011Level' );
            my $loc = getAttributes( $dobj , 'RFC5011Name' );

            my $parent = "$loc.$level.$conf->{zone}";
            ( my $name = $dobj->name() ) =~ s/\.$parent//;

            push @{ $domaindata->{ $level }{ $loc } } , $name ;

        }
    }

    return ( $domaindata );

}

#
# get all the keys from the grid
#
# ALL TXT records tagged as 'key'
#

sub getKeys {
    my ( $conf ) = @_ ;

    # get all the domains and insert them into the config
    # called from loadGridConf

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    my ( @keys ) = $session->search(
        object => "Infoblox::DNS::Record::TXT",
        zone => $conf->{zone},
        extensible_attributes => { RFC5011Type => { value => "key" } }
    );
    getSessionErrors( $session , "list keys" ) if $DEBUG ;

    my $keyData = {};

    # now walk each of them and insert them into the conf
    foreach my $kobj ( @keys ) {
        my $level = getAttributes( $kobj , 'RFC5011Level' );
        my $loc = getAttributes( $kobj , 'RFC5011Name' );
        my $state = getAttributes( $kobj , 'RFC5011State' );

        my $parent = "$loc.$level.$conf->{zone}";

        my ( $id , $domain ) = $kobj->name() 
            =~ /(\d+).key.(\S+).$parent/;

        # perhaps a platter hierarchy, with a single namespced key?
        # [ ] well, execpt that is breaks if there is a special
        #     char in any of the EA values ( e.g. "my:dumb:viewname" )
#         $keyData->{$domain}{$id}{ongrid} = 'true';
        $keyData->{$level}{$loc}{$domain}{$id} = {
            domain => $domain,
            gid => $id,
            level => $level,
            lvlname => $loc,
            time => getAttributes( $kobj , 'RFC5011Time' ),
            state => $state,
        };
    }

    return $keyData ;

}

#
# get all the existing trust anchors configured on the grid
# stored in the 'dnssec_trusted_keys()' part of the DNS settings
#
# return a hash, keyed by location,domain and GID
#

sub getAnchors {
    my ( $conf ) = @_ ;

    # called from loadGridConf()

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # We're ok, continue to configure the grid
    my ( $gobj ) = $session->get(
        object => "Infoblox::Grid::DNS",
    );
    getSessionErrors( $session ,"getAnchors : Infoblox::Grid::DNS"); 

    # no grid properties is bad
    return undef unless $gobj ;

    my $data = {};
    $data->{grid}{default} = getObjectAnchors( $gobj );

    # then find any member or view level settings

    # you can't store EAs on a Infoblox::Grid::Member::DNS object,
    # So we have to get the list of members first
    my @members = $session->get(
        object => "Infoblox::Grid::Member",
        extensible_attributes => { RFC5011Level => { value => "member" } }
    );
    foreach my $mobj ( @members ) {
        my $mname = $mobj->name();
        my ( $mdns ) = $session->get(
            object => "Infoblox::Grid::Member::DNS",
            name => $mname,
        );

        $data->{member}{$mname} = getObjectAnchors( $mdns );
    }

    # and the views
    my @views = $session->get(
        object => "Infoblox::DNS::View",
        extensible_attributes => { RFC5011Level => { value => "view" } }
    );
    foreach my $vobj ( @views ) {
        my $vname = $vobj->name();
        $data->{view}{$vname} = getObjectAnchors( $vobj );
    }

    return $data ;

}

#
# returns a REF to DNS settings somwwhere
# requires level and name ( grid / default )
#
sub getDNSSettings {
    my ( $conf , $level , $name ) = @_ ;

    my %query = (
        object => "Infoblox::Grid::DNS",
    );

    if ( $level eq 'member' ) {
        %query = (
            object => "Infoblox::Grid::Member::DNS",
            name => $name,
        );
    }
    elsif ( $level eq 'view' ) {
        %query = (
            object => "Infoblox::DNS::View",
            name => $name,
        );
    }

    my $session = startSession( $conf );  
    return unless $session ;

    my ( $obj ) = $session->get( %query );
    getSessionErrors( $session ,"getDNSSettings : $level : $name"); 
    return $obj ;

}

#
# extract and format the dnssec_trusted_keys
# for a PAPI object
#
sub getObjectAnchors {
    my ( $obj ) = @_ ;

    my $data = {};

    return unless $obj->dnssec_trusted_keys() ;

    foreach my $gkey ( @{ $obj->dnssec_trusted_keys() } ) {

        my $alg = getAlgorithm ( $gkey->algorithm() );
        my $k = $gkey->key();
        my $domain = $gkey->fqdn();

        # generate a Net::DNS::RR so we can calculate the keyid
        my $keyrr = new Net::DNS::RR("$domain DNSKEY 257 3 $alg $k");

        # we index by keyid, because we want it to be agnostic
        # to any revoke or other flags

        my $id = $keyrr->keyid();
        $data->{ $domain }{ $id } = $gkey ;
    }

    return $data ;
}

#
# session handling
#

sub restartServices {
    my ( $conf ) = @_ ;

    if ( $PASSIVE ) {
        logwarn("passive mode : no DNS service restart");
        return ;
    }

    my $session = startSession( $conf );  
    return unless $session ;

    logit("Requesting DNS service restart");
    # just kick it
    $session->restart(
        service => 'dns',
    );

}

sub startSession {
    my ( $conf ) = @_ ;

    # fancy ref caching
    return $conf->{session} if $conf->{session};

    my $login = $conf->{login};

    my $master = $login->{master};

    logit ( "Connecting to GM $login->{master}" );

    # create the session handler
    my $session = Infoblox::Session->new(
         master => $login->{master},
         username => $login->{username},
         password => $login->{password},
#          password => 'xinfoblox',
#          "timeout" => $login->{timeout},
         "connection_timeout" => $login->{timeout} || 5,
    );

    unless ( $session ) {
        # may need some LWP debug here
        logerror( "Couldn't connect to $login->{master}" );
        logerror( "check username, password or connection" );
    }

    if ( getSessionErrors( $session ) ) {
        $session = undef ;
    }

    # also save it for caching
    $conf->{session} = $session ;

    return $session ;
            
}

#
# general handler to log and show session errors
# return TRUE if there WAS an error
#
sub getSessionErrors {
    my ( $session , $info ) = @_ ;

    if ( $session && $session->status_code() ) {
        my $result = $session->status_code();
        my $response = $session->status_detail();
        logerror( "$response ($result) : $info " );
        return 1;
    }
    return 0;
}

sub getApiErrors {
    my ( $session , $info ) = @_ ;

    my $result = Infoblox::status_code() ;
    my $response = Infoblox::status_detail() ;
    logerror( "$response ($result) : $info " );
    return 1;

}

#
# helper function
#
# objects may not have the EA method or any EAs
#
sub getAttributes {
    my ( $obj , $ea ) = @_ ;
    return undef unless $obj->extensible_attributes();

    return $obj->extensible_attributes()->{$ea}

}

#
# modifying EAs requires special care
#
# we're passed a hashref of EA values
#
sub setAttributes {
    my ( $obj , $attrs ) = @_ ;

    # easy if there aren't any
    unless ( $obj->extensible_attributes() ) {
        $obj->extensible_attributes( $attrs );
        return;
    }

    # otherwise walk the ones we were given and add them to the hash
    my $exts = $obj->extensible_attributes();

    foreach my $ea ( keys %{ $attrs } ) {
        # if you pass a blank, clear it out
        if ( $attrs->{$ea} ) {
            $exts->{$ea} = $attrs->{$ea};
        }
        else {
            delete $exts->{$ea};
        }
    }

    # and update the object
    $obj->extensible_attributes( $exts );
}

#
# PAPI 
# lookup algorithm, coz we don't support all numbers, grr
#

sub getAlgorithm {
    my ( $al ) = @_;

    return $ALGNUMLOOK{$al} if $al =~ /^\d+$/;
    return $ALGLOOK{$al} ;

}

#
# logging
#

sub logerror {
    my ( $message ) = @_ ;
    logit( $message , "ERROR" );
}

sub logwarn {
    my ( $message ) = @_ ;
    logit( $message , "WARN" );
}


sub logit {
    my ( $message , $level ) = @_ ;
    $level = "INFO" unless $level ;

    # ALL mesages come here, where we add a timestamp
    print localtime() . " : $level : $message\n";
}

=head1 DIAGNOSTICS

Use '-d N' to run at different diagnostic/debug levels

The higher the number, the more feedback you get

=over

=item C<< Error message here, perhaps with %s placeholders >>

[Description of error here]

=item C<< Another error message here >>

[Description of error here]

[Et cetera, et cetera]

=back

=head1 DEPENDENCIES

 Storable
 Net::DNS, Net::DNS::Sec
 Infoblox.pm
 Digest::MD5

=head1 INCOMPATIBILITIES

Not all algorithms are supported, as a manual lookup table is required to
convert beteen public and Infoblox supported algorithms

Unicode may be a problem, dependong on the domain name being added as
SEP.

I have not yet thought through other incompatibilities, though there are
most certainly some. I don't like code that is longer than 72 characters
per line, you may hate me for that.



=head1 BUGS 

No bugs have been reported. Yet.

=head1 SEE ALSO

    perldoc, perlfunc

=head1 AUTHOR

Copyright (c) 2015, Geoff Horne, SLC . All rights reserved.

=cut

####################################################

sub setFakeKeys {
    my ( $state , $keydata ) = @_;

    # $keydata is a HASH.
    # usually we can just modify one of the keys
    my ( $tag ) = sort {$a<=>$b} keys %{ $keydata } ;

    
    # the 'invalid' test is in the validateDomainKeys()
    if ( $state =~ /invalid/i ) {
        return ;
    }


    if ( $state =~ /miss|remove/i ) {
        logwarn( "TEST : hide key $tag");
        delete $keydata->{$tag};
    }

    elsif ( $state =~ /revoke/i ) {
        logwarn( "TEST : revoke key $tag");
        $keydata->{$tag}{rdata}->revoke(1);
        $keydata->{$tag}{state} = 'revoked';
    }

    elsif ( $state =~ /add|new/i ) {
        # insert a new valid key

        my $nkey = fakenewkey();
        my $kid = $nkey->keytag();
        logwarn( "TEST : add key $kid");
        $keydata->{$kid} = {
            rdata => $nkey,
            state => 'valid',
        }
#         print Dumper ( $keydata );
#         exit ;
    }



    return $keydata ;

}

sub fakenewkey {
#                 ) ; key id = 30909
    my $comkey = '
    DNSKEY  257 3 8 (
        AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVc
        NcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9
        OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyv
        NPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ
        79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrb
        TQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7A
        SbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2y
        nKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/
    ';

    my $keyrr = new Net::DNS::RR("org $comkey");

    return $keyrr ;

}

#
# placeholders for some test keys
#
sub fakedns {

#                 ) ; key id = 30909
    my $comkey = '
    DNSKEY  257 3 8 (
        AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVc
        NcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9
        OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyv
        NPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ
        79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrb
        TQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7A
        SbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2y
        nKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/
    ';

#                 ) ; key id = 9795
    my $ak = '
    DNSKEY 257 3 7 (
        AwEAAZTjbIO5kIpxWUtyXc8avsKyHIIZ+LjC2Dv8naO+
        Tz6X2fqzDC1bdq7HlZwtkaqTkMVVJ+8gE9FIreGJ4c8G
        1GdbjQgbP1OyYIG7OHTc4hv5T2NlyWr6k6QFz98Q4zwF
        IGTFVvwBhmrMDYsOTtXakK6QwHovA1+83BsUACxlidpw
        B0hQacbD6x+I2RCDzYuTzj64Jv0/9XsX6AYV3ebcgn4h
        L1jIR2eJYyXlrAoWxdzxcW//5yeL5RVWuhRxejmnSVnC
        uxkfS4AQ485KH2tpdbWcCopLJZs6tw8q3jWcpTGzdh/v
        3xdYfNpQNcPImFlxAun3BtORPA2r8ti6MNoJEHU=
    ';


#                 ) ; key id = 21366
    my $kd = '
    DNSKEY 257 3 7
        AwEAAYpYfj3aaRzzkxWQqMdl7YExY81NdYSv+qayuZDo
        dnZ9IMh0bwMcYaVUdzNAbVeJ8gd6jq1sR3VvP/SR36mm
        GssbV4Udl5ORDtqiZP2TDNDHxEnKKTX+jWfytZeT7d3A
        bSzBKC0v7uZrM6M2eoJnl6id66rEUmQC2p9DrrDg9F6t
        XC9CD/zC7/y+BNNpiOdnM5DXk7HhZm7ra9E7ltL13h2m
        x7kEgU8e6npJlCoXjraIBgUDthYs48W/sdTDLu7N59rj
        CG+bpil+c8oZ9f7NR3qmSTpTP1m86RqUQnVErifrH8Kj
        DqL+3wzUdF5ACkYwt1XhPVPU+wSIlzbaAQN49PU=
    ';

    my $keyrr = new Net::DNS::RR("org $kd");

    print Dumper ( $keyrr->keytag() , $keyrr->keyid );

    $keyrr->revoke(1);

    print Dumper ( $keyrr->keytag() , $keyrr->keyid );

}

#
# NET::DNS extensions
#

package Net::DNS::RR::DNSKEY ;

#
# calculates a keytag that ignores the flags,
# so it always returns the same value for the same key
# RFC4034 Appendix B variant
#
# requires $keyrr->keybin();
#
# a re-write of Net::DNS::RR::DNSKEY->keytag()
#

sub keyid {
    my $self = shift ;

    return $self->{keyid} = do {
#         my @kp = @{$self}{qw(flags protocol algorithm)};
        my @kp = ( 0 , 0 , 0 );
        my $kb = $self->{keybin} || return 0;
        my $od = length($kb) & 1;
        my $ac = 0;
        $ac += $_ for unpack 'n*', pack "n C2 a* x$od", @kp, $kb;
        $ac += ( $ac >> 16 );
        $ac & 0xFFFF;
    }

}

