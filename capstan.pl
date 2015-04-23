#!/usr/bin/env perl
#
# Perl common chunks
#
use strict ;
use feature qw(say switch);
use Storable qw( retrieve lock_store );
use Term::ReadKey;

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

# auto include help|?' => pod2usage(2)
use Getopt::Long qw(:config auto_help);
use Pod::Usage;

my $GRIDMASTER ;
my $MEMBER ;
my $USER ;
my $PASS ;
my $INIT ;
my $FORCE ;
my $SHOWCONFIG ;
my $DEBUG ;
my $NOOP ;

# DO NOT SET ANY OTHER GLOBALS, here or anywhere near here
# set the rest in the $conf{} in initConfig()

my $CONFFILE = "$BASE/$SCRIPTNAME.cfg";

GetOptions (
#     "V|version"    => sub { print "\n$ID\n$REV\n\n"; exit ; },
    "d=s"       => \$DEBUG,
    "gm=s"       => \$GRIDMASTER,
    "m=s"       => \$MEMBER,
    "u|user=s"       => \$USER,
    "p=s"       => \$PASS,
    "C"       => \$SHOWCONFIG,
    "init"       => \$INIT,
    "f"       => \$FORCE,
    "n"       => \$NOOP,
);

# 
#     [ ] -m  # set the Nameserver member
#             # and list all members if none set
#     [ ] -p  # passive, don't restart services
#     [ ] -t  # test all key states ( doesn't modify database )
#     [ ] -s  # re-sync all keys (quite the hammer)
#     [ ] -a  # add a domain
#     [ ] -r  # remove a domain
#     [ ] -l  # list domains
#     [ ] -k  # list all key states

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

# [ ] check the commandline options
# unless ( @ARGV ) {
#     die "Usage: $NAME <args>\n";
# }

# load up the local config, the loaders kick errors
my $conf = loadLocalConfig() or exit;

# do some local config settings
setUser( $conf , $USER ) && exit if $USER ;
setMaster( $conf , $GRIDMASTER ) && exit if $GRIDMASTER ;
setMember( $conf , $MEMBER ) && exit if $MEMBER ;

# now talk to the grid and get the systemwide configuration
# to add to the config
loadGridConf( $conf ) or exit;

if ( $SHOWCONFIG ) {
    delete $conf->{login}{password};
    print Dumper ( $conf ) ;
    exit ;
}


#######################################

=head1 NAME

capstan : an implementation of RFC 5011 for Infoblox

=head1 SYNOPSIS

    ./capstan.pl

 Options:

  -help      Show a brief help message
  -C         Show the current configuration
  --init     Initialise the system (only runs once)
             requires --gm and --user

  -m <name>  Set the query nameserver to this member

=head1 OPTIONS

=over 8

=item B<-help>

Print a brief help message and exits.

=back

=head1 DESCRIPTION

=for author to fill in:
    Write a full description of the module and its features here.
    Use subsections (=head2, =head3) as appropriate.

=cut

########################################
# SUBS
########################################

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
#         extensible_attributes => { RFC5011 => { value => "nameserver" } }
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
        $state = getAttributes( $mobj , 'RFC5011' );
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
                setAttributes( $cobj , { RFC5011 => '' } );
                $session->modify( $cobj );
                getSessionErrors( $session ); 
            }
        }

        # then (re) set this member
        setAttributes( $newobj , { RFC5011 => 'nameserver' } );
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
        print "enter password for user $user: ";
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
        zone => "rfc5011.local",
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
    foreach my $ea ( qw( RFC5011
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
        comment => "Auto added by RFC5011 Capstan",
    );
    $session->add( $zobj );
    getSessionErrors( $session , "zone $conf->{zone}" );

    return ;

}

sub loadGridConf {
    my ( $conf ) = @_ ;

    # we're passed the config from disk with the login info
    # so now append to it...

    my $session = startSession( $conf );  
    return unless $session ;

    # search for all grid member objects
    my ( $dnsmember ) = $session->get(
        object => "Infoblox::Grid::Member",
        extensible_attributes => { RFC5011 => { value => "nameserver" } }
    );
    getSessionErrors( $session , "RFC5011 member" );

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
    getSessionErrors( $session , "zone $conf->{zone}" );
    if ( $zobj ) {
        $conf->{zoneOK} = 'true'
    }

    return $conf ;

}

sub loadLocalConfig {

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

    return $data ;

}

sub saveLocalConfig {
    my ( $conf ) = @_ ;
    lock_store $conf , $CONFFILE;
}

#
# session handling
#
sub startSession {
    my ( $conf ) = @_ ;
    my $login = $conf->{login};

    my $master = $login->{master};

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


sub logit {
    my ( $message , $level ) = @_ ;
    $level = "INFO" unless $level ;

    # ALL mesages come here, where we add a timestamp
    print localtime() . " : $level : $message\n";
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
