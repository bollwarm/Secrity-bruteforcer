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
my @hosts=qw(
192.161.1.1
192.161.1.2
192.161.1.3
);

for(@hosts) {

print "Connet to $_ =====================:\n";

my $re=mysql($_,$userc);

if($re){

print $_,":Find Mysql Weak user password :$re";
 

}
}
