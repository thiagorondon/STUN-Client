#!/usr/bin/perl

package STUN::Client;

use Moose;
use Moose::Util::TypeConstraints;

use Socket;
use String::Random qw(random_regex);

our $VERSION = '0.02';

has stun_server => (
    is => 'rw',
    isa => 'Str'
);

has port => (
    is => 'rw',
    isa => 'Int',
    default => 3478, 
);

has 'local_address' => (
    is => 'rw',
    isa => 'Str'
);

has 'local_port' => (
    is => 'rw',
    isa => 'Int',
    default => 0
);

has proto => (
    is => 'rw',
    isa => enum([qw[tcp udp]]),
    default => 'udp',
);

has 'transaction_id' => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => random_regex('[0-9A-F]{16}')
);

has 'retries' => (
    is => 'rw',
    isa => 'Int',
    default => 5
);

has 'timeout' => (
    is => 'rw',
    isa => 'Int',
    default => 2
);

has 'method' => (
    is => 'rw',
    isa => 'Str',
    default => '0001'
);

has 'data' => (
    is => 'rw',
    isa => 'Str',
    default => ''
);

has 'data_len' => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => sub {
        my $self = shift;
        sprintf("%04d", length($self->data));
    }
);

sub _select {
    my ($self, $rinh) = @_;
    my ($rin, $win, $ein);
    $rin = $win = $ein = '';
    vec($rin,fileno($rinh), 1) = 1;
    $ein = $rin;
    my ($rout, $wout, $eout);
    my $nfound = select($rout=$rin, $wout=$win, $eout=$ein, $self->timeout);
    return $nfound;
}

sub run () {
    my ($self) = @_;

    socket(S, PF_INET, SOCK_DGRAM, getprotobyname($self->proto));

    if ($self->local_address) {
        my $bind_addr = gethostbyname($self->local_address)
            || die "$0: Couldn't bind.\n";
        my $bind_sin = sockaddr_in($self->local_port, $bind_addr);
        bind(S, $bind_sin) || die "$0: Couldn't bind $!\n";
    }

    my $iaddr = gethostbyname($self->stun_server);
    my $sin = sockaddr_in($self->port, $iaddr);

    my $msg = pack('nna[16]',
                $self->method, 
                $self->data_len,
                $self->transaction_id
            );

    my $try = 0;

    while (++$try <= $self->retries) {
        my $s = send(S, $msg, 0, $sin);
        defined $s && $s == length($msg) || die "send: $!";

        # Timeout
        next if !$self->_select(\*S);

        my $rmsg = '';
        my $r = recv(S, $rmsg, 1024, 0);
        # || die "recv: $!";

        next if !defined $r;

        my ($r_message_type, $r_message_length, $r_transaction_id,
            $r_attr_type, $r_attr_length,
            $r_ma_dummy, $r_ma_family,
            $r_ma_port, $r_ma_address) =
                unpack("nna[16]" . "nn" . "bbna[4]",
                    $rmsg);

        my $ret = { 
            r_message_type => $r_message_type,
            r_message_length => $r_message_length,
            r_transaction_id => $r_transaction_id,
            r_attr_type => $r_attr_type,
            r_attr_length => $r_attr_length,
            r_ma_dummy => $r_ma_dummy,
            r_ma_family => $r_ma_family,
            r_ma_port => $r_ma_port,
            r_ma_address => inet_ntoa($r_ma_address)
        };
        #$self->stun_return($ret);
        return $ret;
    }
}


1;

__END__

=head1 NAME

STUN::Client - STUN Client. (RFC 5389)

=head1 SYNOPSIS

    use STUN::Client;
    use Data::Dumper;

    $stun_client = STUN::Client->new;

    $stun_client->stun_server('stun.server.org');
    $r = $stun_client->run;

    print Dumper($r);

=head1 DESCRIPTION

Session Traversal Utilities for NAT (STUN) is a protocol that serves as a tool for other protocols in dealing with Network Address Translator (NAT) traversal. It can be used by an endpoint to determine the IP address and port allocated to it by a NAT. It can also be used to check connectivity between two endpoints, and as a keep-alive protocol to maintain NAT bindings. STUN works with many existing NATs, and does not require any special behavior from them.
                
STUN is not a NAT traversal solution by itself. Rather, it is a tool to be used in the context of a NAT traversal solution.

=head1 ATTRIBUTES

=head2 stun_server

=head2 port

=head2 local_address

=head2 local_port

=head2 proto

=head2 retries

=head2 timeout

=head2 method

=head2 data

=head1 METHODS

=head2 run

=head1 AUTHOR

Thiago Rondon, <thiago@aware.com.br>

http://www.aware.com.br/

=head1 LICENSE

Perl license.


