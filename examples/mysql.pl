use Secrity::bruteforcer::mysql;


my @hosts=qw(
192.161.1.1
192.161.1.2
192.161.1.3
192.161.1.4

);
for(@hosts) {
 mysql $_;

}

