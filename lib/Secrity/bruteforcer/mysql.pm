
use lib ".";
use BMYSQL;
use strict;
use Data::Dumper;
our $VERSION = '0.01';

my $DEBUG = 0;

my @hosts = qw(
  192.168.1.1
  192.168.1.2
  192.168.1.3
  192.168.1.4
  192.168.1.5
  192.168.1.6
);

my @usrs = ( 'root', 'test', 'mysql' );
my @pws = (
    '123456',    'admin',      'root',         'toor!@#',
    'ftp',       'password',   '123123',       '123',
    '1',         '{user}',     '{user}{user}', '{user}1',
    '{user}123', '{user}2016', '{user}!@#',    '{user}2015',
    '{user}!',   '',           'P@ssw0rd!!',   'qwa123',
    '12345678',  'test',       '123qwe!@#',    '123456789',
    '123321',    '1314520',    '666666',       'woaini',
    'fuckyou',   '000000',     '1234567890',   '8888888',
    'qwerty',    '1qaz2wsx',   'abc123',       'abc123456',
    '1q2w3e4r',  '123qwe',     '159357',       'p@ssw0rd',
    'p@55w0rd',  'password!',  'p@ssw0rd!',    'password1',
    'r00t',      'tomcat',     'apache',       'system'
);

for (@hosts) {

    #print "Connet to $_ =====================:\n";
    my $re = mysql($_);

    if ($re) {

        print $_, ":Find Mysql Weak user password :$re";

    }
}

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
