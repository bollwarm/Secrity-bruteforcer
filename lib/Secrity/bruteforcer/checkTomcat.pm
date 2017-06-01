package Secrity::bruteforcer::checkTomcat;

use 5.006;
use LWP;
use LWP::Simple;
use LWP::UserAgent;
require Exporter;
use strict;
use warnings;

our $VERSION = '0.01';
my $DEBUG = 0;
our @ISA    = qw(Exporter);
our @EXPORT = qw(tomcatV);

=head1 NAME

Secrity::bruteforcer::checkTomcat - Check the tomcat version!

=head1 VERSION

Version 0.01

=cut


sub tomcatV { 
my($ip,$port)=@_;

my $url='http://'.$ip.':'.$port.'/zzz';
my $ua = LWP::UserAgent->new;
$ua->agent("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36");
#print $url,"\n";
my $cont=$ua->get($url);
#print  Dumper($cont);
unless($cont->content eq "") {
my $conts=$cont->content;
my @cont=split /\n/,$conts;
my $rese;

for(@cont){
if ($_=~m/Apache Tomcat\/([^\s]+)/) {

$rese=$1 ;
return "$url :: Apache Tomcat ",$rese."\n";
}
}
return $url,"\n";
}

return;
}
