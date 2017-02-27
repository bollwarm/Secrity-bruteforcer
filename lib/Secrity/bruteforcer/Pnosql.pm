package Pnosql;

use 5.004;
use IO::Socket;
use Carp;
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

my @usrs = qw();

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

    #print "Connet to $_ =====================:\n";
    my $re = checkredis($_,'6379',2);
             checkmemcache($_,'11211',2);
             checkmongo($_,'271017',2);
    if ($re) {
        
        my $auth=checkauth();
        print $_, ":Find Mysql Weak user password :$auth";

    }

  
}

sub checkport {

my ($host,$port,$timeout,$comm,$res)=@_;

my $connect = IO::Socket::INET->new(
    
  PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => $timeout || 20,
) or carp "Couldn't connect to $_:$port/tcp: $@";

if($connect ) {
$connect->send( $comm, 0 );

my $BUFFER_LENGTH = 1024;
my $auth_result;

$connect->recv( $auth_result, $BUFFER_LENGTH, 0 );

print "unauthorized" if $auth_result =~ /$res/;

return 1 if $auth_result =~ /Authentication/;

}

}

sub checkredis {

 my ($host,$port,$timeout)=@_;

 my $comm='INFO\r\n';
 my $res='redis_version';
 return checkport($host,$port,$timeout,$comm,$res);

}
sub checkmemcache {

 my ($host,$port,$timeout)=@_;

 my $comm='stats\r\n';
 my $res='version';
 return checkport($host,$port,$timeout,$comm,$res);

}
sub checkmongo {


my ($host,$port,$timeout)=@_;

my $connect = IO::Socket::INET->new(

  PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => $timeout || 20,
) or carp "Couldn't connect to $_:$port/tcp: $@";

if($connect ) {

my $data = hex2bin("3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000");
$connect->send( $data, 0 );
my $BUFFER_LENGTH = 1024;
my $auth_result;
$connect->recv( $auth_result, $BUFFER_LENGTH, 0 );
if ($auth_result =~ /ismaster/) {
my $getlog_data = hex2bin("480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000");
               
my $log_result;
 $connect->recv($log_result, $BUFFER_LENGTH, 0 );
 print "unauthorized" if $log_result=~ /totalLinesWritten/;


}

}

}

sub hex2bin {

#my $hstr='3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000';
my $hstr=shift;
my $result;
for (my $i = 0; 1; $i++) {
           my $offset = 2 * $i;
            if ($b = substr($hstr, $offset, 2)) {
                $b = hex $b;
                $b=sprintf "%b", $b;
                $result.=$b;
            } else {
                last;
            }
}
return  $result;
}

sub checkauth {

my ( $host,$port,$user,$pass,$timeout,$auth_result)=@_;

    for (@usrs) {
        my $user = $_;
        for (@pws) {
            my $pwd = $_;
            $pwd =~ s/\{user\}/$user/g if /\{user\}/;

       my $connect  = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto    => 'tcp',
            Timeout  => $timeout || 20,
          )
          or carp "Couldn't connect to $host:$port/tcp: $@";

        $connect->send( "AUTH $pwd\r\n", 0 );
        my $BUFFER_LENGTH = 1024;
        my $auth_result;
        $connect->recv( $auth_result, $BUFFER_LENGTH, 0 );

       return "username:$user,password:$pass" if $auth_result =~ /\+OK/;

}

}

}

