use Secrity::bruteforcer;
use Secrity::bruteforcer::mysql;

my (@hosts,$user,$pass);

my $info=config("config.ini");

$user=$info->{mysqluser};
$pass=$info->{mysqlpassword};

my $userc={
user => $user,
pass => $pass,

};
=pod
print $_,"\n" for(@{$userc->{user}});
for(@{$userc->{pass}}) {
s/^'//;
s/'$//;
print ;
print "\n";
}
=cut
my @hosts=qw(
192.161.1.1
192.161.1.2
192.161.1.3
192.161.1.4

);
for(@hosts) {
 
 mysql $_,$userc;

}

