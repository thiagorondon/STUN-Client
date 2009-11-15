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

has 'response' => (
    is => 'rw',
    isa => 'HashRef'
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

        my ($message_type, $message_length, $transaction_id,
            $attr_type, $attr_length,
            $ma_dummy, $ma_family,
            $ma_port, $ma_address) =
                unpack("nna[16]" . "nn" . "bbna[4]",
                    $rmsg);

        my $ret = { 
            message_type => $message_type,
            message_length => $message_length,
            transaction_id => $transaction_id,
            attr_type => $attr_type,
            attr_length => $attr_length,
            ma_dummy => $ma_dummy,
            ma_family => $ma_family,
            ma_port => $ma_port,
            ma_address => inet_ntoa($ma_address)
        };
        $self->response($ret);
        return $ret;
    }
}


1;

__END__

=head1 NAME

STUN::Client - Session Traversal Utilities for NAT (STUN) client. (RFC 5389)

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

Hostname of STUN server.

=head2 proto

Protocol to use for connect, 'udp' or 'tcp'. 

Default: udp.

=head2 port

Port number of STUN server.

Default: 3478

=head2 local_address

Local Internet address.

=head2 local_port

Local port number, but it is necessary that local_address is explicity.

=head2 retries

The client retries the request, this time including its username and the
realm, and echoing the nonce provided by the server.  The client also
includes a message-integrity, which provides an HMAC over the entire
request, including the nonce.  The server validates the nonce and
checks the message integrity.  If they match, the request is
authenticated.  If the nonce is no longer valid, it is considered
"stale", and the server rejects the request, providing a new nonce.

Default: 5

=head2 timeout

Retransmit a STUN request message starting with an interval of RTO ("Retransmission TimeOut"), doubling after each retransmission.

Default: 2

=head2 method

STUN methods in the range 0x000 - 0x7FF are assigned by IETF Review
[RFC5226].  STUN methods in the range 0x800 - 0xFFF are assigned by
Designated Expert [RFC5226].

=head2 data

Data to send in package.

=head1 METHODS

=head2 run

Connect to a stun_server and receive the answer.

=head1 STUN Servers

    * stun.ekiga.net
    * stun.fwdnet.net
    * stun.ideasip.com
    * stun01.sipphone.com (no DNS SRV record)
    * stun.softjoys.com (no DNS SRV record)
    * stun.voipbuster.com (no DNS SRV record)
    * stun.voxgratia.org (no DNS SRV record)
    * stun.xten.com
    * stunserver.org see their usage policy
    * stun.sipgate.net:10000 

=head1 AUTHOR

Thiago Rondon, <thiago@aware.com.br>

http://www.aware.com.br/

=head1 LICENSE

Perl license.


