package Secrity::bruteforcer::Pnosql;

use 5.004;
use IO::Socket;
use Carp;
use strict;
use warnings;

our $VERSION = '0.01';
my $DEBUG = 0;

our @ISA    = qw(Exporter);
our @EXPORT = qw(checkredis checkmongo checkmemcache checkZookeeper);

=head1 NAME

Secrity::bruteforcer::Pnosql - Check the vulnerability of nosql includding redis monogdb memcache zookeeper!

=head1 VERSION

Version 0.01

=cut

my (@usrs,@pws);

sub checkport {

    my ( $host, $port, $timeout, $comm, $res ) = @_;

   print "Function checkport() begin check $host : $port \n" if $DEBUG;
    my $connect = IO::Socket::INET->new(

        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout || 10,
    ) or carp "Couldn't connect to $_:$port/tcp: $@";

    if ($connect) {
        $connect->send( $comm, 0 );

        my $BUFFER_LENGTH = 1024;
        my $auth_result;

        $connect->recv( $auth_result, $BUFFER_LENGTH, 0 );
        
        if($auth_result =~ /$res/) {
        print "\e[35;31;1mUnauth Server\e[0m $host Port $port:"; #服务未启动认证，存在严重安全问题
        return $auth_result; 
        }
        #return 1 if $auth_result =~ /Authentication/; # 需要用户认证

    }

}

sub checkredis {

    my ( $host, $port, $timeout ) = @_;

    my $comm = "INFO\n";
    my $res  = 'redis_version';
    my $result= checkport( $host, $port, $timeout, $comm, $res );
    my $ver=$1 if $result=~/redis_version:(.*)\n/;
    my   $os=$1 if $result=~/os:(.*)\n/;
    my   $conf=$1 if $result=~/config_file:(.*)\n/;
    print "Redis $ver\n";
    print "Server os: $os\n";
    print "conf files: $os\n";

}

sub checkZookeeper {

    my ( $host, $port, $timeout ) = @_;
    print "Function checkport() begin check $host : $port \n" if $DEBUG;
    my $comm = 'envi';
    my $res  = 'Environment';
    my $result=checkport( $host, $port, $timeout, $comm, $res ); 
    my $outer=$1 if $result=~/zookeeper.version=(.*)/;
    print "zookeeper $outer \n";
    
    
}

sub checkmemcache {

    my ( $host, $port, $timeout ) = @_;

    my $comm = "stats\r\n";
    my $res  = 'version';
    return checkport( $host, $port, $timeout, $comm, $res );

}

sub checkmongo {

    my ( $host, $port, $timeout ) = @_;

    my $connect = IO::Socket::INET->new(

        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout || 20,
    ) or carp "Couldn't connect to $_:$port/tcp: $@";

    if ($connect) {

        my $data = hex2bin(
"3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000"
        );
        $connect->send( $data, 0 );
        my $BUFFER_LENGTH = 1024;
        my $auth_result;
        $connect->recv( $auth_result, $BUFFER_LENGTH, 0 );
        if ( $auth_result =~ /ismaster/ ) {
            my $getlog_data = hex2bin(
"480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000"
            );

            my $log_result;
            $connect->recv( $log_result, $BUFFER_LENGTH, 0 );
            print "unauthorized" if $log_result =~ /totalLinesWritten/;

        }

    }

}

sub hex2bin {

    my $hstr = shift;
    my $result;
    for ( my $i = 0 ; 1 ; $i++ ) {
        my $offset = 2 * $i;
        if ( $b = substr( $hstr, $offset, 2 ) ) {
            $b = hex $b;
            $b = sprintf "%b", $b;
            $result .= $b;
        }
        else {
            last;
        }
    }
    return $result;
}

sub checkauth {

    my ( $host, $port, $user, $pass, $timeout, $auth_result ) = @_;

    for (@usrs) {
        my $user = $_;
        for (@pws) {
            my $pwd = $_;
            $pwd =~ s/\{user\}/$user/g if /\{user\}/;

            my $connect = IO::Socket::INET->new(
                PeerAddr => $host,
                PeerPort => $port,
                Proto    => 'tcp',
                Timeout  => $timeout || 20,
            ) or carp "Couldn't connect to $host:$port/tcp: $@";

            $connect->send( "AUTH $pwd\r\n", 0 );
            my $BUFFER_LENGTH = 1024;
            my $auth_result;
            $connect->recv( $auth_result, $BUFFER_LENGTH, 0 );

            return "username:$user,password:$pass" if $auth_result =~ /\+OK/;

        }

    }

}

1;
