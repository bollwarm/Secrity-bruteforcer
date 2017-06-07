use Secrity::bruteforcer::Pnosql;


my @hosts=qw(
192.161.1.1
192.161.1.2
192.161.1.3
192.161.1.4

);
for(@hosts) {
 checkZookeeper( $_, '2181', 2 );

}

