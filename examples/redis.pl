use Secrity::bruteforcer::Pnosql;


my @hosts=qw(
10.1.2.1
10.1.2.2
10.1.2.3
10.1.2.4
);
for(@hosts) {
checkredis( $_, '6379', 2 );

}

