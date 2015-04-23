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
my $USER ;
my $PASS ;
my $INIT ;
my $FORCE ;
my $SHOWCONFIG ;
my $DEBUG ;
my $NOOP ;

my $CONFFILE = "$BASE/$SCRIPTNAME.cfg";

GetOptions (
#     "V|version"    => sub { print "\n$ID\n$REV\n\n"; exit ; },
    "d=s"       => \$DEBUG,
    "gm=s"       => \$GRIDMASTER,
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
my $loginconf = loadLocalConfig() or exit;

# do some local config settings
setUser( $loginconf , $USER ) && exit if $USER ;
setServer( $loginconf , $GRIDMASTER ) && exit if $GRIDMASTER ;

# now talk to the grid and get the systemwide configuration
my $conf = loadGridConf( $loginconf ) or exit;

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

sub setServer {
    my ( $conf , $gm ) = @_ ;

    logit( "Changing Gridmaster to : $gm" );

    # re/set and save the GM to the local config
    $conf->{master} = $gm ;

    saveLocalConfig( $conf );

    return ;
}

# get a password, save and write the config
sub setUser {
    my ( $conf , $user ) = @_ ;

    logit( "Changing login user to : $user" );

    $conf->{username} = $user ;

    # hack to bypass the prompt
    my $password = $PASS || undef ;

    unless ( $password ) {
        # just prompt for a username
        print "enter password for user $user: ";
        ReadMode 2;
        chomp(my $password=<STDIN>);
        ReadMode 0;
        print "\n";
    }

    $conf->{password} = $password;

    saveLocalConfig( $conf );

    # return the config, just in case we needed it
    return ;
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
        master => $server,
        timeout => 5,
        username => "",
        password => "",
    };

    # get a password for the username
    # ( or we can't talk to the grid and configure it);
    # and let setUser write the config to disk

    setUser( $conf, $user );

#     # now try and connect to the grid and make some other settings
    my $session = startSession( $conf );  

    return ;

}

sub sessionErrors {
    my ( $session ) = @_ ;
    if ( $session && $session->status_code() ) {
        my $result = $session->status_code();
        my $response = $session->status_detail();
        logerror( "$response ($result)" );
        return 1;
    }
    return 0;
}

sub loadGridConf {
    my ( $login ) = @_ ;

    # we're passed the local login config from disk
    # use that to bootstrap the config.
    # And load some settings from the grid

    my $session = startSession( $login );  
    return unless $session ;

    # search for all grid member objects
    my ( $dnsmember ) = $session->get(
        object => "Infoblox::Grid::Member",
        extensible_attributes => { RFC5011 => { value => "nameserver" } }
    );

    sessionErrors( $session );

    # insert it into the main config
    my $conf = {
        login => $login
    };

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
    my ( $login ) = @_ ;

    my $master = $login->{master};

    # create the session handler
    my $session = Infoblox::Session->new(
         "master" => $login->{master},
         "username" => $login->{username},
         "password" => $login->{password},
#          "timeout" => $login->{timeout},
         "connection_timeout" => $login->{timeout} || 5,
    );

    unless ( $session ) {
        # may need some LWP debug here
        logerror( "Couldn't connect to $login->{master}" );
    }

    if ( sessionErrors( $session ) ) {
        $session = undef ;
    }

    return $session ;
            
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
