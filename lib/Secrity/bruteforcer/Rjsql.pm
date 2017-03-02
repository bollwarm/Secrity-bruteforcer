package Rjsql;

#!/usr/bin/perl	-w
use strict;
use IO::Socket;
use LWP::UserAgent;
use LWP::Protocol::https;    # in case	of HTTPS
use List::Compare;           # compare	web pages



my $ua = LWP::UserAgent->new;    # now spoof a UA:
$ua->agent(
"Mozilla/5.0 (Windows;U;Windows NT 6.1 en-US;rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18"
);
$ua->from('admin@google.com');
$ua->timeout(10);                #setup a timeout

my $usage = "./bg <host> <port>\n";
my $web   = 0;                        #	token for web
my $host  = shift or die $usage;
my $port  = shift or die $usage;
my $buf;                              #	buffer for returned result
my @content;                          #	split()	content	returned from query
my @gets;                             #	GET parameters present
my @tables;                           #	all tables from individual loop
my $reqCount = 0;                     #	keep track of requests
my $injType  = "int";                 #	injection type (start with integer)
my $colCount = 0;                     #	column count
my $injectString;                     # injectable field query with -VAR- variable

my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto    => "tcp"
) || die "Cannot connect to " . $host;
$sock->send("HEAD/HTTP/1.1\r\n");
$sock->send("\r\n");
$sock->send("\r\n");
$sock->recv( $buf, 2048 );
my @buf = split( "\n", $buf );

foreach (@buf) {

    #if (m/^Server:(.*)/i) || (m/address>(.*)Server)/i) {
    if (m/address>(.*)Server/i) {
        print "\aWeb Server Found: ", $1, "\n";
        $web++;
    }
}

if ($web) { # this is a confirmed web server
    foreach ( "html", "htm", "php", "asp", "aspx", "cfm", "txt", "html.backup" )
    {
        if ( page( "test." . $_ ) ) {
            print "Page: ", "index." . $_ . "\n";
            foreach (@content) {
                if (m/<a.*href=("|')([^"']+)("|')/) {
                    print "File:", $2, "\n";
                    my $file = $2;
                    if ( $file =~ m/\?[^=]+=[^=]+/i ) {
                        push( @gets, $file );  # keep it
                    }
                }
            }
            last;                              # we found a page
        }
    }
}
if ( scalar @gets > 0 ) {                      # we have some URLs with GET
    foreach my $getUrl (@gets) {
        my $url = $getUrl;
        $url =~ s/(\?[^=]+=)[0-9a-z_]/$1%27/;   # %27 is an encoded single quote
        print "Trying mangled	GET:	", $url, "\n";
        page($url);                             # get the mangled URL
        foreach my $domLine (@content) {        # look for error
            print "Positive MySQL injection: ", $url, "\n"
              if ( $domLine =~ m/error.*syntax.*sql/i );
        }
    }
}

sub page {                                      # check for pages
    my $res = $ua->get( "http://" . $host . ":" . $port . "/" . $_[0] );
    if ( $res->is_success ) {
        @content = split( /\015?\012/, $res->content );
        return $_[0];
    }
    return 0;
}

END {
    $sock->close() if $sock;
}
