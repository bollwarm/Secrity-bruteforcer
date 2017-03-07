
package Secrity::bruteforcer::checkTomcat;

use 5.006;
use IO::Socket;
use strict;
use warnings;



our $VERSION = '0.01';

my $DEBUG = 0;
use LWP;
use LWP::Simple;
use LWP::UserAgent;
use Data::Dumper;
use HTTP::Cookies;
use HTTP::Headers;
use HTTP::Response;
use Encode;
use URI::Escape;
use URI::URL;
use utf8;
binmode(STDOUT, ':encoding(utf8)');

=head1 NAME

Secrity::bruteforcer::checkTomcat - Check the tomcat version!

=head1 VERSION

Version 0.01

=cut


my $hp = <<'HP'
192.168.1.1 8080
192.168.1.2 8080
192.168.1.3 80
HP
;

my @hp=split /\n/sm,$hp;

print $hp[0],"\n";
print $hp[-1],"\n";

my %hosts;

for(@hp) {
my ($h,$p)=split;
$hosts{$h}=$p;

}
for(keys %hosts) {
 print  tomcatV($_,$hosts{$_});


}

sub tomcatV { 
my($ip,$port)=@_;

my $url='http://'.$ip.':'.$port.'/zzz';
my $ua = LWP::UserAgent->new;
$ua->agent("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36");

#my $respos= $ua->get("https://raysnote.com/users/sign_in");
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
