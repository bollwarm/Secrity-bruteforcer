package Secrity::bruteforcer::BMYSQL;

use 5.004;
use IO::Socket;
use Carp;
use vars qw($VERSION $DEBUG);
use strict;
$VERSION = '0.01';

use constant COMMAND_SLEEP          => "\x00";
use constant COMMAND_QUIT           => "\x01";
use constant COMMAND_INIT_DB        => "\x02";
use constant COMMAND_QUERY          => "\x03";
use constant COMMAND_FIELD_LIST     => "\x04";
use constant COMMAND_CREATE_DB      => "\x05";
use constant COMMAND_DROP_DB        => "\x06";
use constant COMMAND_REFRESH        => "\x07";
use constant COMMAND_SHUTDOWN       => "\x08";
use constant COMMAND_STATISTICS     => "\x09";
use constant COMMAND_PROCESS_INFO   => "\x0A";
use constant COMMAND_CONNECT        => "\x0B";
use constant COMMAND_PROCESS_KILL   => "\x0C";
use constant COMMAND_DEBUG          => "\x0D";
use constant COMMAND_PING           => "\x0E";
use constant COMMAND_TIME           => "\x0F";
use constant COMMAND_DELAYED_INSERT => "\x10";
use constant COMMAND_CHANGE_USER    => "\x11";
use constant COMMAND_BINLOG_DUMP    => "\x12";
use constant COMMAND_TABLE_DUMP     => "\x13";
use constant COMMAND_CONNECT_OUT    => "\x14";

use constant DEFAULT_PORT_NUMBER => 3306;
use constant BUFFER_LENGTH       => 1460;
use constant DEFAULT_UNIX_SOCKET => '/tmp/mysql.sock';

sub new {
    my $class = shift;
    my %args  = @_;

    my $self = bless {
        hostname             => $args{hostname},
        unixsocket           => $args{unixsocket} || DEFAULT_UNIX_SOCKET,
        port                 => $args{port} || DEFAULT_PORT_NUMBER,
        database             => $args{database},
        user                 => $args{user},
        password             => $args{password},
        timeout              => $args{timeout} || 40,
        'socket'             => undef,
        salt                 => '',
        protocol_version     => undef,
        client_capabilities  => 0,
        affected_rows_length => 0,
    }, $class;
    $self->debug( $args{debug} );

    #        $self->_initialize or return;

    my $mysql;
    if ( $self->{hostname} ) {
        printf "Use INET Socket: %s %d/tcp\n", $self->{hostname}, $self->{port}
          if $self->debug;
        $mysql = IO::Socket::INET->new(
            PeerAddr => $self->{hostname},
            PeerPort => $self->{port},
            Proto    => 'tcp',
            Timeout  => $self->{timeout} || 40,
          )
          or carp "Couldn't connect to $self->{hostname}:$self->{port}/tcp: $@";
    }
    else {
        printf "Use UNIX Socket: %s\n", $self->{unixsocket} if $self->debug;
        $mysql = IO::Socket::UNIX->new(
            Type => SOCK_STREAM,
            Peer => $self->{unixsocket},
        ) or carp "Couldn't connect to $self->{unixsocket}: $@";
    }
    if ($mysql) {
        $mysql->autoflush(1);
        $self->{succect_code} = 0;
        $self->{socket}       = $mysql;
        $self->_get_server_information;
        return $self;
    }

}

sub login {
    my $self = shift;
    my ( $user, $password ) = @_;
    $self->{user}     = $user;
    $self->{password} = $password;
    $self->_request_authentication;

}

sub close {
    my $self  = shift;
    my $mysql = $self->{socket};
    return unless $mysql->can('send');

    my $quit_message =
      chr( length(COMMAND_QUIT) ) . "\x00\x00\x00" . COMMAND_QUIT;
    $mysql->send( $quit_message, 0 );
    $self->_dump_packet($quit_message) if BMYSQL->debug;
    $mysql->close;
}

sub is_succect {
    my $self = shift;
    $self->{succect_code} = 1;
}

sub get_succect {
    my $self = shift;
    return $self->{succect_code};
}

sub is_error {
    my $self = shift;
    $self->{error_code} ? 1 : undef;
}

sub get_error_code {
    my $self = shift;
    $self->{error_code};
}

sub get_error_message {
    my $self = shift;
    $self->{server_message};
}

sub debug {
    my $class = shift;
    $DEBUG = shift if @_;
    $DEBUG;
}

sub _get_server_information {
    my $self  = shift;
    my $mysql = $self->{socket};

    my $message;
    $mysql->recv( $message, BUFFER_LENGTH, 0 );
    $self->_dump_packet($message)
      if BMYSQL->debug;
    my $i = 0;
    my $packet_length = ord substr $message, $i, 1;
    $i += 4;
    $self->{protocol_version} = ord substr $message, $i, 1;
    printf "Protocol Version: %d\n", $self->{protocol_version}
      if BMYSQL->debug;

    if ( $self->{protocol_version} == 10 ) {
        $self->{client_capabilities} = 1;
    }

    ++$i;
    my $string_end = index( $message, "\0", $i ) - $i;
    $self->{server_version} = substr $message, $i, $string_end;
    printf "Server Version: %s\n", $self->{server_version}
      if BMYSQL->debug;

    $i += $string_end + 1;
    $self->{server_thread_id} = unpack 'v', substr $message, $i, 2;
    $i += 4;
    $self->{salt} = substr $message, $i, 8;
    #
    $i += 8 + 1;
    if ( length $message >= $i + 1 ) {
        $i += 1;
    }
    if ( length $message >= $i + 18 ) {

        # get server_language
        # get server_status
    }
    $i += 18 - 1;
    if ( length $message >= $i + 12 - 1 ) {
        $self->{salt} .= substr $message, $i, 12;
    }
    printf "Salt: %s\n", $self->{salt} if BMYSQL->debug;

}

sub _request_authentication {
    my $self  = shift;
    my $mysql = $self->{socket};
    $self->_send_login_message();

    my $auth_result;
    $mysql->recv( $auth_result, BUFFER_LENGTH, 0 );
    $self->_dump_packet($auth_result) if BMYSQL->debug;
    if ( $self->_is_error($auth_result) ) {
        $mysql->close;
        if ( length $auth_result < 7 ) {

            #        carp "Timeout of authentication";
        }

        # warn substr $auth_result, 7;
        $self->{succect_code} = 0;
        return 0;
    }
    $self->is_succect;
    print "connect database\n" if BMYSQL->debug;

}

sub _send_login_message {
    my $self  = shift;
    my $mysql = $self->{socket};
    my $body =
        "\0\0\x01\x0d\xa6\03\0\0\0\0\x01"
      . "\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
      . join "\0", $self->{user},
      "\x14"
      . BMYSQL::Password->scramble( $self->{password}, $self->{salt},
        $self->{client_capabilities} );
    $body .= $self->{database};
    $body .= "\0";
    my $login_message = chr( length($body) - 3 ) . $body;
    $mysql->send( $login_message, 0 );
    $self->_dump_packet($login_message) if BMYSQL->debug;
}

sub _execute_command {
    my $self    = shift;
    my $command = shift;
    my $sql     = shift;
    my $mysql   = $self->{socket};

    my $message = pack( 'V', length($sql) + 1 ) . $command . $sql;
    $mysql->send( $message, 0 );
    $self->_dump_packet($message) if BMYSQL->debug;

    my $result;
    $mysql->recv( $result, BUFFER_LENGTH, 0 );
    $self->_dump_packet($result) if BMYSQL->debug;
    $self->_reset_status;

    if ( $self->_is_error($result) ) {
        return $self->_set_error_by_packet($result);
    }
    elsif ( $self->_is_select_query_result($result) ) {
        return $self->_get_record_by_server($result);
    }
    elsif ( $self->_is_update_query_result($result) ) {
        return $self->_get_affected_rows_information_by_packet($result);
    }
    else {
        croak 'Unknown Result: ' . $self->_get_result_length($result) . 'byte';
    }
}

sub _set_error_by_packet {
    my $self   = shift;
    my $packet = shift;

    my $error_message = $self->_get_server_message($packet);
    $self->{server_message} = $error_message;
    $self->{error_code}     = $self->_get_error_code($packet);
    return undef;
}

sub _is_error {
    my $self   = shift;
    my $packet = shift;
    return 1 if length $packet < 4;
    ord( substr $packet, 4 ) == 255;
}

sub _get_server_message {
    my $self   = shift;
    my $packet = shift;
    return '' if length $packet < 7;
    substr $packet, 7;
}

sub _get_error_code {
    my $self   = shift;
    my $packet = shift;
    $self->_is_error($packet)
      or croak "_get_error_code(): Is not error packet";
    unpack 'v', substr $packet, 5, 2;
}

sub _reset_status {
    my $self = shift;
    $self->{insert_id}       = 0;
    $self->{server_message}  = '';
    $self->{error_code}      = undef;
    $self->{selected_record} = undef;
}

sub _has_next_packet {
    my $self = shift;
    return substr( $_[0], -5, 1 ) ne "\xfe";
}

sub _dump_packet {
    my $self          = shift;
    my $packet        = shift;
    my ($method_name) = ( caller(1) )[3];
    my $str           = sprintf "%s():\n", $method_name;
    while ( $packet =~ /(.{1,16})/sg ) {
        my $line = $1;
        $str .= join ' ', map { sprintf '%02X', ord $_ } split //, $line;
        $str .= '   ' x ( 16 - length $line );
        $str .= '  ';
        $str .= join '',
          map { sprintf '%s', (/[\w\d\*\,\?\%\=\'\;\(\)\.-]/) ? $_ : '.' }
          split //, $line;
        $str .= "\n";
    }
    print $str;

    #warn $str;
}

package BMYSQL::Password;
use strict;
use Digest::SHA1;

sub scramble {
    my $class     = shift;
    my $password  = shift;
    my $hash_seed = shift;
    return '' unless $password;
    return '' if length $password == 0;
    return _make_scrambled_password( $hash_seed, $password );
}

sub _make_scrambled_password {
    my $message  = shift;
    my $password = shift;

    my $ctx = Digest::SHA1->new;
    $ctx->reset;
    $ctx->add($password);
    my $stage1 = $ctx->digest;

    $ctx->reset;
    $ctx->add($stage1);
    my $stage2 = $ctx->digest;

    $ctx->reset;
    $ctx->add($message);
    $ctx->add($stage2);
    my $result = $ctx->digest;
    return _my_crypt( $result, $stage1 );
}

sub _my_crypt {
    my $s1     = shift;
    my $s2     = shift;
    my $l      = length($s1) - 1;
    my $result = '';
    for my $i ( 0 .. $l ) {
        $result .= pack 'C',
          (
            unpack( 'C', substr( $s1, $i, 1 ) ) ^
              unpack( 'C', substr( $s2, $i, 1 ) ) );
    }
    return $result;
}

package BMYSQL::Password32;
use strict;

sub scramble {
    my $class               = shift;
    my $password            = shift;
    my $hash_seed           = shift;
    my $client_capabilities = shift;

    return '' unless $password;
    return '' if length $password == 0;

    my $hsl = length $hash_seed;
    my @out;
    my @hash_pass = _get_hash($password);
    my @hash_mess = _get_hash($hash_seed);

    my ( $max_value, $seed,  $seed2 );
    my ( $dRes,      $dSeed, $dMax );
    if ( $client_capabilities < 1 ) {
        $max_value = 0x01FFFFFF;
        $seed      = _xor_by_long( $hash_pass[0], $hash_mess[0] ) % $max_value;
        $seed2     = int( $seed / 2 );
    }
    else {
        $max_value = 0x3FFFFFFF;
        $seed      = _xor_by_long( $hash_pass[0], $hash_mess[0] ) % $max_value;
        $seed2     = _xor_by_long( $hash_pass[1], $hash_mess[1] ) % $max_value;
    }
    $dMax = $max_value;

    for ( my $i = 0 ; $i < $hsl ; $i++ ) {
        $seed  = int( ( $seed * 3 + $seed2 ) % $max_value );
        $seed2 = int( ( $seed + $seed2 + 33 ) % $max_value );
        $dSeed = $seed;
        $dRes  = $dSeed / $dMax;
        push @out, int( $dRes * 31 ) + 64;
    }

    if ( $client_capabilities == 1 ) {

        # Make it harder to break
        $seed  = ( $seed * 3 + $seed2 ) % $max_value;
        $seed2 = ( $seed + $seed2 + 33 ) % $max_value;
        $dSeed = $seed;

        $dRes = $dSeed / $dMax;
        my $e = int( $dRes * 31 );
        for ( my $i = 0 ; $i < $hsl ; $i++ ) {
            $out[$i] ^= $e;
        }
    }
    return join '', map { chr $_ } @out;
}

sub _get_hash {
    my $password = shift;

    my $nr  = 1345345333;
    my $add = 7;
    my $nr2 = 0x12345671;
    my $tmp;
    my $pwlen = length $password;
    my $c;

    for ( my $i = 0 ; $i < $pwlen ; $i++ ) {
        my $c = substr $password, $i, 1;
        next if $c eq ' ' || $c eq "\t";
        my $tmp = ord $c;
        my $value = ( ( _and_by_char( $nr, 63 ) + $add ) * $tmp ) + $nr * 256;
        $nr = _xor_by_long( $nr, $value );
        $nr2 += _xor_by_long( ( $nr2 * 256 ), $nr );
        $add += $tmp;
    }
    return ( _and_by_long( $nr, 0x7fffffff ),
        _and_by_long( $nr2, 0x7fffffff ) );
}

sub _and_by_char {
    my $source = shift;
    my $mask   = shift;

    return $source & $mask;
}

sub _and_by_long {
    my $source = shift;
    my $mask = shift || 0xFFFFFFFF;

    return _cut_off_to_long($source) & _cut_off_to_long($mask);
}

sub _xor_by_long {
    my $source = shift;
    my $mask = shift || 0;

    return _cut_off_to_long($source) ^ _cut_off_to_long($mask);
}

sub _cut_off_to_long {
    my $source = shift;

    if ( $] >= 5.006 ) {
        $source = $source % ( 0xFFFFFFFF + 1 ) if $source > 0xFFFFFFFF;
        return $source;
    }
    while ( $source > 0xFFFFFFFF ) {
        $source -= 0xFFFFFFFF + 1;
    }
    return $source;
}

1;
