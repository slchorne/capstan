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

my $GRIDMASTER ;
my $MEMBER ;
my $USER ;
my $PASS ;

my $INIT ;
my $SHOWCONFIG ;
my $SHOWLOCALCONFIG ;

my $ADD;
my $REMOVE;
my $LISTDOMAINS;
my $LISTKEYS;

my $DEBUG ;
my $NOOP ;
my $FORCE ;
my $XRES ; # dummy test offline resolver

# DO NOT SET ANY OTHER GLOBALS, here or anywhere near here
# set the rest in the $conf{} in initConfig()

my $CONFFILE = "$BASE/$SCRIPTNAME.cfg";
my $AUTOCOMM = "Auto added by RFC5011 Capstan";

my $ores = GetOptions (
#     "V|version"    => sub { print "\n$ID\n$REV\n\n"; exit ; },
    "gm=s"      => \$GRIDMASTER,
    "m=s"       => \$MEMBER,
    "u|user=s"  => \$USER,
    "p=s"       => \$PASS,

    "a=s"     => \$ADD,
    "r=s"     => \$REMOVE,
    "l"       => \$LISTDOMAINS,
    "k"       => \$LISTKEYS,

    "C"       => \$SHOWCONFIG,
    "c"       => \$SHOWLOCALCONFIG,
    "init"    => \$INIT,
    "f"       => \$FORCE,

    "d=s"     => \$DEBUG,
    "n"       => \$NOOP,
    "x=s"     => \$XRES, # local test hack
);

exit unless $ores;

#     [ ] -k  # list all key states
#     [ ] -p  # passive, don't restart services
#     [ ] -t  # test all key states ( doesn't modify database )
#     [ ] -s  # re-sync all keys (quite the hammer)

#######################################

=head1 NAME

capstan : an implementation of RFC 5011 for Infoblox

=head1 SYNOPSIS

  ./capstan.pl

  ./capstan.pl --init --gm my.grid.master --user admin

  ./capstan.pl -a org 

 Options:

  -a <domain>   Add a domain to track
  -f <file>     txt file with DNSKEYS
  -r <domain>   Remove a domain to track
  -l            List tracked domains
  -k            List tracked keys

  -help      Show a brief help message
  -C         Show the current configuration
  -c         Show just the local configuration
  --init     Initialise the system (only runs once)
             requires --gm and --user

  -m <name>  Set the query nameserver to this member
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
setMember( $conf , $MEMBER ) && exit if $MEMBER ;

# now talk to the grid and get the systemwide configuration
# to add to the config
loadGridConf( $conf ) or exit;

showConfig( $conf ) && exit if $SHOWCONFIG ; 

# adding domains requires key validation, 
# and essentially everything that relates to the grid config
# so we may as well pull the whole config, coze we don't get any
# performance gain by bypassing this step (and we would just dupe a messy
# pile o' code

addDomain( $conf , $ADD ) && exit if $ADD;
delDomain( $conf , $REMOVE ) && exit if $REMOVE;

# strictly speaking these on-offs could happen before
# calling loadGridConf(), but by doing them here, and just checking the
# config, we have slightly cleaner code
listDomains( $conf ) && exit if $LISTDOMAINS ;
listKeys( $conf ) && exit if $LISTKEYS ;

# Step one, query all the Keys out in the real workd

checkAllKeys( $conf );

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
# Revoked -> Removed : if revoked key is not ins RREST for N? time
# 
#     DO NOT publish this key, and never re-publish this key
#   Removed -> /dev/null
# And a removed key is no-longer of concern


# step 2 add any new keys
# [ ] this follows the statemachine,
#     we're just testing for now

# [ ] 
discoKey( $conf , 'com' , '30909' ) ;

#
publishKey( $conf , 'com' , '30909' );


exit ;

########################################
# SUBS
########################################

=head1 OPTIONS

=head2 -a <domain>

Add a domain to the tracker

This will create a TXT record in the rfc5011.local zone for the namespace
of the tracked domain

=cut

#
# Add a domain to the tracker
#

sub addDomain {
    my ( $conf , $domain ) = @_ ;

    # adding a domain requires using an existing trust anchor
    # so we just use the config to query the grid and DNS
    # and return any valid anchors for this domain as a list of IDs

    my ( $anchorids , @keys ) = validateAnchor( $conf , $domain );

    return 1 unless $anchorids ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # add the domain to be tracked to the zone
    logit( "Adding tracking domain $domain");

    my $level = 'grid';
    my $fqdn = join ( "." , $domain , $level , $conf->{zone} );

    my $tobj = Infoblox::DNS::Record::TXT->new(
        name => $fqdn,
        text => "domain:$domain loc:$level",
        comment => $AUTOCOMM,
        extensible_attributes => { 
            RFC5011Level => $level,
            RFC5011Name => $level,
            RFC5011Type => 'domain' 
        },
    );
            
    $session->add( $tobj );
    getSessionErrors( $session , "domain $fqdn" );

    # then add and the valid key as a trackable anchor
    foreach my $id ( @{ $anchorids } ) {
        addKey( $conf , {
            domain => $domain,
            id => $id,
            level => $level,
            location => $level,
            state => 'valid',
            info => "",
        });

    }

    # lastly add any OTHER keys for this domain as pending
    # we can throw away the query data after this, because we will
    # do another query if we need to later.

    # we have 2 lists here, so there is no cleaner way to do this

    logit( "Adding additional keys from domain $domain");
    foreach my $rr ( @keys ) {
        my $id = $rr->keytag() ;
        
        next if ( grep ( /^$id$/ , @{ $anchorids } ) );

        addKey( $conf , {
            domain => $domain,
            id => $id,
            level => $level,
            location => $level,
            state => 'pending',
#             info => "",
        });

    }

    return 1 ;

}

=head2 -r <domain>

Remove a domain to the tracker

This will remove the matching TXT record in the rfc5011.local zone for
the namespace of the tracked domain

=cut

sub delDomain {
    my ( $conf , $domain ) = @_ ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # remove the domain to be tracked
    my $level = 'grid';
    my $parent = join ( "." , $domain , $level , $conf->{zone} );

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

=head2 -l 

List all the domains being tracked

This will get all the TXT records in the rfc5011.local zone where the
extensible_attribute 'RFC5011Type' == 'domain'

=cut

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
            ( my $name = $dobj->name() ) =~ s/\.$conf->{zone}//;
            my $level = getAttributes( $dobj , 'RFC5011Level' );
            my $loc = getAttributes( $dobj , 'RFC5011Name' );

            $domaindata->{ $loc }{ $loc } = $name ;

        }
    }

    return ( $domaindata );

}

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
        my ( $id , $domain ) = $kobj->name() 
            =~ /(\d+).key.(\S+).$conf->{zone}/;

        my $level = getAttributes( $kobj , 'RFC5011Level' );
        my $loc = getAttributes( $kobj , 'RFC5011Name' );
        my $state = getAttributes( $kobj , 'RFC5011State' );

        # perhaps a platter hierarchy, with a single namespced key?
        # [ ] well, execpt that is breaks if there is a special
        #     char in any of the EA values ( e.g. "my:dumb:viewname" )
#         $keyData->{$domain}{$id}{ongrid} = 'true';
        $keyData->{$level}{$loc}{$domain}{$id} = {
            ongrid => 'true',
            query => 'not found',
            state => $state,
        };
    }

    return $keyData ;

}

sub getAnchors {
    my ( $conf , $domain , $id , $info ) = @_ ;

    # get all the existing trust anchors configured on the grid
    # called from loadGridConf()

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # We're ok, continue to configure the grid
    my ( $gobj ) = $session->get(
        object => "Infoblox::Grid::DNS",
    );
    getSessionErrors( $session ); 

    my $data = {};
    # walk all the anchors, and index them by domain and digest
    foreach my $gkey ( @{ $gobj->dnssec_trusted_keys() } ) {
        my $digest = md5_base64( $gkey->{key} );
        $data->{ $gkey->fqdn() }{$digest} = $gkey ;
    }

    return $data ;

}

#
# add a key to the zone file for tracking
#
sub addKey {
    my ( $conf , $rec ) = @_ ;

    # we have to set some defaults of the PAII will choke on
    # invalid/blank EA values
    my $id = $rec->{id};
    my $domain = $rec->{domain};
    my $level = $rec->{level} || 'grid' ;
    my $location = $rec->{location} || 'grid' ;
    my $state = $rec->{state} || 'start' ;
    my $info = $rec->{info};

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    # add the domain to be tracked
    my $fqdn = join ( "." , $id , 'key' , $domain , $level , $conf->{zone} );

    # add the tracking zone
    logit( "Adding key $id for $domain as $state");

    my $tobj = Infoblox::DNS::Record::TXT->new(
        name => $fqdn,
        text => "domain:$domain id:$id loc:$level",
        comment => $AUTOCOMM,
        extensible_attributes => { 
            RFC5011Time => time(),
            RFC5011State => $state,
            RFC5011Level => $level,
            RFC5011Name => $location,
            RFC5011Type => 'key' 
        },
    );
            
    $session->add( $tobj );
    getSessionErrors( $session , "key $fqdn" );

    return 1 ;

}

#
# add a key to the grid properties
# 
sub publishKey {
    my ( $conf , $domain , $id , $info ) = @_ ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    logit( "Trusting key $id for $domain");

    # get the config for this key
    my $rdata = $conf->{keys}{$domain}{$id}{rr};

    unless ( $rdata ) {
        logerror( "rdata for key $id was not found" );
        return ;
    }

    # We're ok, continue to configure the grid
    my ( $gobj ) = $session->get(
        object => "Infoblox::Grid::DNS",
    );
    getSessionErrors( $session ); 

    my $gridkeys = $gobj->dnssec_trusted_keys();

    print Dumper ( (caller(0))[3] , $rdata ) if $DEBUG ;

    # create and add the key object
    # [ ] hope that it isn't already there...

    my $keydef = Infoblox::DNS::DnssecTrustedKey->new(
           fqdn => $domain,
           algorithm => getAlgorithm( $rdata->{algorithm} ),
#            algorithm => $rdata->{algorithm},
           key => $rdata->{key},
    );
    getApiErrors() unless $keydef ;

    push @{ $gridkeys } , $keydef ;

    # update and modify
    $gobj->dnssec_trusted_keys( $gridkeys );

    $session->modify( $gobj );
    getSessionErrors( $session ); 

    return 1 ;

}

#
# remove a key to the grid properties
#   disco(ontinue)Key
# 
sub discoKey {
    my ( $conf , $domain , $id , $info ) = @_ ;

    # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  
    return unless $session ;

    logit( "UnTrusting key $id for $domain");

    # get the config for this key we want to remove
    my $rdata = $conf->{keys}{$domain}{$id}{rr};
    unless ( $rdata ) {
        logerror( "rdata for key $id was not found" );
        return ;
    }

    # We're ok, continue to configure the grid
    my ( $gobj ) = $session->get(
        object => "Infoblox::Grid::DNS",
    );
    getSessionErrors( $session ); 

    my $digest = $rdata->{digest};

    print Dumper ( (caller(0))[3] , $rdata ) if $DEBUG ;

    # need to walk all the keys on the grid, but these have no good UID,
    # and a regex will fail on the keystring.
    # so md5_base64() the key, and compare it to the digest in the config

    my $newkeys = [];

    # [ ] this is now done at load time, we can just examine the config
    foreach my $gkey ( @{ $gobj->dnssec_trusted_keys() } ) {
#         my $gsum = md5_base64( $gkey->{key} );

        if ( md5_base64( $gkey->{key} ) eq $rdata->{digest} ) {
            logit( "Removing $domain $id $rdata->{digest}" );
        }
        else {
            push @{ $newkeys } , $gkey ;
        }
    }

    $gobj->dnssec_trusted_keys( $newkeys );

    $session->modify( $gobj );
    getSessionErrors( $session ); 

    return 1 ;

}

#
# set the grid ember for querying to,
# OR list All members if it wasn't found
# also remove the EA from any other member
#
sub setMember {
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
    foreach my $mobj ( @members ) {
        my $name = $mobj->name();
        my $ip = $mobj->ipv4addr();
        my $state = "";

        # see if this member is the query member
        # and track it for cleanup
        $state = getAttributes( $mobj , 'RFC5011Type' );
        push @cleanmembers , $mobj  if $state ;
#         if ( $mobj->extensible_attributes()
#             && $mobj->extensible_attributes()->{RFC5011}
# #             ) {
#                 $state = $mobj->extensible_attributes()->{RFC5011} ;
#         }

        # OR if this is the new member
        if ( $name eq $member ) {
            logit( "setting $member as query nameserver" );
            $newobj = $mobj ;
        }

        # we could have overlaps here if you re-set the current
        # nameserver member, but that will be OK

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
        ReadMode 2;
        chomp($password=<STDIN>);
        ReadMode 0;
        print "\n";
    }

    $login->{password} = $password;

    saveLocalConfig( $conf );

    # return the config, just in case we needed it ?
    # must return OK
    return 1 ;
}

#
# format key data from the conf
#
sub listKeys {

    local $Data::Dumper::Terse = 1 ;
    local $Data::Dumper::Maxdepth = 4 ;
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

    my @k = traverseKeys( $conf , "", 'keys' );
#     my @k = traverseKeys( $conf->{keys} , "", keys %{ $conf->{keys} } );
    print Dumper ( \@k );

    return 1;
}

# functional code, only ever pass singletons
sub traverseKeys {
    # note the implicit shift of the array
    my ( $rec , $path , $val , @keys ) = @_;

    # bubble up an array
    my @res ;

    # across
    push @res , traverseKeys( $rec , $path , @keys ) if @keys ;

    my $newpath = $path ? "$path : $val" : $val ;

    # exit condition
    return "$newpath" if $val =~ /\d/;

    # down
    push @res , traverseKeys( $rec->{$val} , "$newpath",
                    keys %{ $rec->{$val} } ) 
            if $rec->{$val} =~/HASH/ ;

    return @res ;

}

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
    foreach my $ea ( qw( RFC5011Type
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

    logit( "Loading grid config..." );

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

#
# DNS queries and resolver stuff handling
#

sub validateAnchor {
    my ( $conf , $domain ) = @_ ;

    # when the config loaded, we got the current anchors from the grid
    # and indexed them by their digest.
    # so we just use that data as the bootstrap point

    my $anchors = $conf->{anchors}{$domain};
    unless ( $anchors ) {
        logerror( "No trust anchor(s) loaded for : $domain" );
        return 0;
    }

    logit("Validating existing anchors for $domain in DNS");

    # We don't have the key ID for this Anchor, and the 'algorithm'
    # string is a bit messed up, so the safest thing to do is to 
    # query the DNS source and verify that these keys are published keys
    # and use the ID from those published keys

    my $keys = querybyType( $conf , $domain , 'DNSKEY' );
    # now index these keys by their digest, but only keep SEP keys
    my $keyindex ;
    foreach my $krr ($keys->answer) {
        next unless $krr->sep();
        $keyindex->{ md5_base64 ( $krr->key() ) } = $krr;
    }
#     my $keyindex = { map { md5_base64 ( $_->key() ) => $_ } $keys->answer };

    # THEN get the signatures, and index them by the ID
    # and filter them by the right type

    # this loop [ ] may become a generic method
    my $sigs = querybyType( $conf , $domain , 'RRSIG' );

    my $sigindex ;
    # now find the right SIGs for our project and put them in an index
    foreach my $rr ($sigs->answer) {
        next unless $rr->typecovered() eq 'DNSKEY';
        $sigindex->{ $rr->keytag() } = $rr ;
    }

    # so now compare the anchors on the grid with the keys
    # we pulled from DNS
    my $validIDs ;
    my $badkeys ;

    # compare by matching the md5_base64() digest
    foreach my $digest ( keys %{ $anchors } ) {
        unless ( $keyindex->{$digest} ) {
            # [ ] one bad key kinda ruins the batch
            #     (If you are adding a new domain to track)
            logerror( "key $anchors->{$digest}{key}");
            logerror( "Anchor : $digest : is not a published key" );

            $badkeys++;
            next ;
        }

        # otherwise this key checks out, lets double check
        # and validate it. Since the digests match, we can use the
        # RR in the dataset
        
        my $keyrr = $keyindex->{$digest};
        my $id = $keyrr->keytag();

        unless ( $keyrr->sep() ){
            logerror( "Anchor : $digest is not a SEP key" );
            $badkeys++;
            next ;
        }

        # find the matching signature
        my $sigrr = $sigindex->{ $id };
        unless ( $sigrr ) {
            logerror( "Anchor : $digest : $id : missing RRSIG" );
            $badkeys++;
            next ;
        }

        # now try and verify this signature with our orignal key
        # and the queried keyset
        if ( $sigrr->verify( [ $keys->answer ], $keyrr ) ) {
            logit( "Anchor : $digest : $id : is valid" );
            push @{ $validIDs } , $id ;
        }
        else {
            logerror( "Anchor : $digest : $id : " . $sigrr->vrfyerrstr ) ;
            $badkeys++;
        }

    }

    # lastly, we don't know the full context of this validate request,
    # so we need to also pass back the keys we found to the parent and let
    # that decide what to do with them

    # any bad key ruins the batch
    if ( $badkeys ) {
        logit( "Cannot add '$domain' without a valid set of anchors" );
        return undef ;
    }
    else {
        return ( $validIDs , values %{ $keyindex } );
    }

}

#
# [ ] GN:DN ??
#
# inserts a list of Net::DNS:RR objects into the 'keys' part of the
# config.
#
# also flags those records with some sort of state
#
sub addKeyRRsToConfig {
    my ( $conf , $state , @rrlist ) = @_ ;

    foreach my $rr ( @rrlist ) {

        my $id = $rr->keytag() ;

#         # and add the dnsinfo to the config
#         $conf->{keys}{$domain}{$id}{state} = $state,
#         $conf->{keys}{$domain}{$id}{query} = "ok";
#         $conf->{keys}{$domain}{$id}{rr} = {
#             flags => $rr->flags(),
#             sep => $rr->sep(),
#             # we need the WHOLE key for the trust anchor
#             key => $rr->key(),
#             # and keep an MD5 sum for repairs and regex
#             digest => md5_base64 ( $rr->key() ),
#             algorithm => $rr->algorithm(),
# #                     key => substr($rr->key(), -8, 8),
#             private => $rr->privatekeyname(),
#             tag => $rr->keytag(),
#         }

    }
}



#

#
# Generic DNS loopup operation
# DNS lookup with error checking, returns Net::DNS::Packet" object
#
sub querybyType {
    my ( $conf , $fqdn , $type ) = @_ ;
    my $resolver = getResolver( $conf );

    logit( "Querying $fqdn for $type");
    # get ALL the DNSKEYS for this domain
    my $rrs = $resolver->send($fqdn , $type, "IN");
    # $query is a a "Net::DNS::Packet" object
    if ( ! $rrs ) {
        # we got an error
        logerror( "$type Search : $fqdn : " . $resolver->errorstring );
    }
    return $rrs ;
}

#
# [ ] GN:DN ?
#
sub validateKey {
    my ( $conf , $domain , $id, $keyrr ) = @_ ;
    logit("Validating key for $domain in DNS");

    my $resolver = getResolver( $conf );

    logit( "Querying $domain for DNSKEY");
    # get ALL the DNSKEYS for this domain
    my $keys = $resolver->send($domain , "DNSKEY", "IN");
    # $query is a a "Net::DNS::Packet" object
    if ( ! $keys ) {
        # we got an error
        logerror( "DNSKEY Search : $domain : " . $resolver->errorstring );
        return 0 ;
    }
    my @allkeys = $keys->answer;

    logit( "Querying $domain for RRSIG");
    # get all the RRSIG stuff
    my $sigs = $resolver->send($domain , "RRSIG", "IN");
    if ( ! $sigs ) {
        # we got an error
        logerror( "RRSIG Search : $domain : " . $resolver->errorstring );
        return 0 ;
    }

    # now find the right SIG for our project
    my $sigrr ;
    foreach my $rr ($sigs->answer) {
        next unless $rr->typecovered() eq 'DNSKEY';
        next unless $rr->keytag() eq $id;

        # this one should match
        $sigrr = $rr ;

        print Dumper ( $rr ) if $DEBUG > 2 ;
    }

    unless ( $sigrr ) {
        logit( "No RRSIG for id $id found");
        return 0;
    }

    # now try and verify this signature with our orignal key
    if ( $sigrr->verify( \@allkeys , $keyrr ) ) {
        logit( "key : $id : is valid" );
        return 1 ;
    }
    else {
        logerror( "key : $id : " . $sigrr->vrfyerrstr ) ;
    }

    return 0 ;

}

sub checkAllKeys {
    my ( $conf ) = @_ ;
    my $resolver = getResolver( $conf );

    foreach my $domain ( @{ $conf->{domains} } ) {    
        logit( "Query keys for $domain" );

        # [ ] do we continue on DNS errors, or just give up ?

        my $reply = $resolver->send($domain , "DNSKEY", "IN");
        # $query is a a "Net::DNS::Packet" object
        if ( ! $reply ) {
            # we got an error
            logerror( "DNSKEY Search : $domain : " . $resolver->errorstring );
            next ;
        }

        foreach my $rr ($reply->answer) {

            # we only care about 'SEP' keys
            if ( $rr->sep ) {
                my $id = $rr->keytag() ;

                # see if we already know about it..
                unless ( $conf->{keys}{$domain}{$id} ) {

                    # [ ] 
                    my $level = 'grid';
                    addKey( $conf , {
                        domain => $domain,
                        id => $id,
                        level => $level,
                        location => $level,
                        info => "",
                    });

                    $conf->{keys}{$domain}{$id}{ongrid} = 'new'
                }

                # and add the dnsinfo to the config
                $conf->{keys}{$domain}{$id}{query} = "ok";
                $conf->{keys}{$domain}{$id}{rr} = {
                    flags => $rr->flags(),
                    sep => $rr->sep(),
                    # we need the WHOLE key for the trust anchor
                    key => $rr->key(),
                    # and keep an MD5 sum for repairs and regex
                    digest => md5_base64 ( $rr->key() ),
                    algorithm => $rr->algorithm(),
#                     key => substr($rr->key(), -8, 8),
                    private => $rr->privatekeyname(),
                    tag => $rr->keytag(),
                }

            }

#             print Dumper ({
#             });

        }

    }

    print Dumper ( (caller(0))[3] , $conf->{keys} ) if $DEBUG ;

}

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
# session handling
#
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

#
# lookup algorithm, coz we don't support all numbers, grr
#

sub getAlgorithm {
    my ( $num ) = @_;

    my $alook = {
        1=>"RSAMD5",
        3=>"DSA",
        5=>"RSASHA1",
        6=>"NSEC3DSA",
        7=>"NSEC3RSASHA1",
        8=>"RSASHA256",
        10=>"RSASHA512",
#         12=>"GOST R 34.10-200",
#         13=>"ECDSA/SHA-256",
#         14=>"ECDSA/SHA-384",
    };

    return ( $alook->{$num} );
}



=head1 DIAGNOSTICS

Use '-d N' to run at different riagnostic/debug levels

The higher the number, the more feedback you get

=over

=item C<< Error message here, perhaps with %s placeholders >>

[Description of error here]

=item C<< Another error message here >>

[Description of error here]

[Et cetera, et cetera]

=back


=head1 DEPENDENCIES

=for author to fill in:
    A list of all the other modules that this module relies upon,
    including any restrictions on versions, and an indication whether
    the module is part of the standard Perl distribution, part of the
    module's distribution, or must be installed separately. ]

None.


=head1 INCOMPATIBILITIES

I have not yet thought through incompatibilities, though there are
most certainly some. I don't like code that is longer than 72 characters
per line, you may hate me for that.

=head1 BUGS 

No bugs have been reported. Yet.

=head1 SEE ALSO

    perldoc, perlfunc

=head1 AUTHOR

Copyright (c) 2015, Geoff Horne, SLC . All rights reserved.

=cut
