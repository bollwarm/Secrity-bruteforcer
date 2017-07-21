package Secrity::bruteforcer;

use 5.006;
use strict;
use warnings;
require Exporter;
=head1 NAME

Secrity::bruteforcer - The great new Secrity::bruteforcer!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

our @ISA    = qw(Exporter);
our @EXPORT = qw(config);

my $dispatch_table ={
mysqluser  => \&set_user,
mysqlpassword => \&set_pass,
};

sub config{

my $file=shift;
return read_config($file,$dispatch_table);
}

sub read_config{

  my ($filename, $actions) = @_;
  my $user;
  open my($CF), $filename or return; # Failure

  while (<$CF>) {
    chomp;
    my ($directive, $rest) = split /\s+/, $_, 2;
    if (exists $actions->{$directive}) {
      $user->{$directive}=$actions->{$directive}->($rest);
    } else {
      die "Unrecognized directive $directive on line $. of $filename; aborting";
    }
  }
  
  return $user; # Success
}

sub set_user {

my $user = shift;
my @value= split /\|/,$user;
return \@value;
}

sub set_pass {

my $user = shift;
my @value= split /\|/,$user;
return \@value;
}


=head1 SYNOPSIS


my $hp = <<'HP'
192.168.1.1 8080
192.168.1.2 8080
192.168.1.3 80
HP
;

my @hp=split /\n/sm,$hp;

print $hp[0],"\n";
print $hp[-1],"\n";

my %hosts;

for(@hp) {
my ($h,$p)=split;
$hosts{$h}=$p;

}
for(keys %hosts) {
 print  tomcatV($_,$hosts{$_});


}









my $DEBUG = 0;

my @hosts = qw(
  192.168.1.1
  192.168.1.2
  192.168.1.3
  192.168.1.4
  192.168.1.5
  192.168.1.6
);

my @usrs = ( 'root', 'test', 'mysql' )

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






ftp


my @hosts = qw(

  ftp.jaist.ac.jp
  192.168.1.1
  192.168.1.2
  192.168.1.3
  192.168.1.4
  192.168.1.5
  192.168.1.6
);

my @usrs =
  ( 'ftp', 'www', 'admin', 'root', 'db', 'wwwroot', 'data', 'web', 'media' );
my @pws = (
    '123456',     'admin',        'root',       'ftp',
    'password',   '123123',       '123',        '1',
    '{user}',     '{user}{user}', '{user}1',    '{user}123',
    '{user}2016', '{user}!@#',    '{user}2015', '{user}!',
    '',           'P@ssw0rd!!',   'qwa123',     '12345678',
    'test',       '123qwe!@#',    '123456789',  '123321',
    '1314520',    '666666',       'woaini',     'fuckyou',
    '000000',     '1234567890',   '8888888',    'qwerty',
    '1qaz2wsx',   'abc123',       'abc123456',  '1q2w3e4r',
    '123qwe',     '159357',       'p@ssw0rd',   'p@55w0rd',
    'password!',  'p@ssw0rd!',    'password1',  'r00t',
    'tomcat',     'apache',       'system'
);


for (@hosts) {

    my $re = ftp($_);

    if ($re) {
        print $_, ": Anonymous opened! \n" if $re =~ /ftp/;
        print $_, ": Weak user and password :$re ! \n";

    }
}




nodql




my @hosts = qw(
192.168.1.1
192.168.2.1
10.2.12.40
);

my @usrs = qw(root);

my @pws = qw(
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

    print "Connet to $_ =====================:\n";
    my $re = checkredis( $_, '6379', 2 );

for (@hosts) {

    print "Connet to $_ =====================:\n";
    my $re = checkredis( $_, '6379', 2 );

    checkmemcache( $_, '11211', 2 );

    checkZookeeper( $_, '2181', 2 );

    checkmongo( $_, '271017', 2 );

 if ($re) {

        my $auth = checkauth();
        print $_, ":Find Redis Weak user password :$auth";

    }

}



=head1 AUTHOR

ORANGE, C<< <bollwarm at ijz.me> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-secrity-bruteforcer at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Secrity-bruteforcer>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Secrity::bruteforcer


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Secrity-bruteforcer>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Secrity-bruteforcer>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Secrity-bruteforcer>

=item * Search CPAN

L<http://search.cpan.org/dist/Secrity-bruteforcer/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2017 ORANGE.

This program is released under the following license: Perl


=cut

1; # End of Secrity::bruteforcer
