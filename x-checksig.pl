#!/usr/bin/env perl
#
# Perl common chunks
#
use strict ;
use feature qw(say switch);
use Digest::MD5 qw(md5_base64);

use Data::Dumper;
$Data::Dumper::Sortkeys = 1 ;

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
use Getopt::Long qw(:config auto_help);
use Pod::Usage;

my $RESOLVER ;
my $DEBUG ;
my $NOOP ;

GetOptions (
#     "V|version"    => sub { print "\n$ID\n$REV\n\n"; exit ; },
    "r=s"       => \$RESOLVER,
    "d=s"       => \$DEBUG,
    "n"       => \$NOOP,
);

unless ( $RESOLVER && @ARGV ) {
    die "Usage: $NAME -r <resolver> <domain>\n";
}

my $DOMAIN = shift ;

# set up the DNS resolver
my $res = Net::DNS::Resolver->new;
$res->nameservers( $RESOLVER );
$res->tcp_timeout(10);
$res->udp_timeout(5);

# get the DNSKEY RRSET for this name

my $keys = $res->send($DOMAIN , "DNSKEY", "IN");
say "DNSKEY Search : $DOMAIN : " . $res->errorstring ;
# $reply is a a "Net::DNS::Packet" object

# then get the RRSIG stuff
my $sigs = $res->send($DOMAIN , "RRSIG", "IN");
say "RRSIG Search : $DOMAIN : " . $res->errorstring ;
# $reply is a a "Net::DNS::Packet" object

# now, we only care about some signatures, (and some keys),
# so walk all the sigs and index them by the keytag so we can find them
# later

my $sigindex ;
foreach my $rr ($sigs->answer) {
    # only want sigs for keys
    next unless $rr->typecovered() eq 'DNSKEY';

    my $tag = $rr->keytag();

    my $rec = {
        rr => $rr,
        info => {
            covers => $rr->typecovered(),
            algorithm => $rr->algorithm(),
            tag => $rr->keytag(),
            labels => $rr->labels(),
            sigexpiration => $rr->sigexpiration(),
            siginception => $rr->siginception(),
            signame => $rr->signame(),
#         signature => $rr->signature(),
            digest => md5_base64 ( $rr->signature() ),
        }
    };

    $sigindex->{ $tag } = $rec ;

    print Dumper ( $rec->{info} );

}

# now assemble the RRset for validating, and walk the keys checking that
# our trust keys have a good signature

# verify has 3 parts,
# - the signature
# - the RR(set)
# - the key
# And it is called as a method on the signature rr:
# 
#     $sigrr->verify ( [ $rr ] , $keyrr )
# 
# The rrset is the WHOLE rrset for thay type, e.g. ALL DNSKEY,
# not just the trusted keys
# 

my @allkeys = $keys->answer;

say "Validating Keys:";

# then walk those RRsets, and track the keys by their tag
foreach my $rr ($keys->answer) {

    # we only care about 'SEP' keys
    next unless $rr->sep();

    my $tag = $rr->keytag();

    my $rec = {
        rr => $rr,
        info => {
            type => $rr->type(),
            flags => $rr->flags(),
            sep => $rr->sep(),
            # we need the WHOLE key for the trust anchor
#         key => $rr->key(),
            # and keep an MD5 sum for repairs and regex
            digest => md5_base64 ( $rr->key() ),
            algorithm => $rr->algorithm(),
#                     key => substr($rr->key(), -8, 8),
            private => $rr->privatekeyname(),
            tag => $rr->keytag(),
        }
    } ;

    print Dumper ( $rec->{info} );

    # when validating, the signature keytag says which key was used to sign
    # now try and validate this signature, find the matching key
    my $sig = $sigindex->{ $tag }{rr} ;
    my $key = $rr ;
    unless ( $sig ) {
        say "No sig for tag : $tag : found" ;
        next ;
    }

    # then try and validate
    if ( $sig->verify( \@allkeys , $key ) ) {
        print "OK : ";
    }
    else {
        print "Error : ";
    }

    say "sig for key : $tag : " . $sig->vrfyerrstr ;

}

