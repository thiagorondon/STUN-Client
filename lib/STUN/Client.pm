#!/usr/bin/perl

package STUN::Client;

use Moose;

use Socket;
use String::Random qw(random_regex);

our $VERSION = '0.01';

has stun_server => (
    is => 'rw',
    isa => 'Str'
);

has port => (
    is => 'rw',
    isa => 'Int',
    default => 3478, 
);

has 'source_address' => (
    is => 'rw',
    isa => 'Str'
);

has proto => (
    is => 'rw',
    isa => enum([qw[tcp udp]]),
    default => 'udp',
);

has 'sock' => (
    is => 'ro',
    isa => 'Object',
    lazy => 1,
    default => sub {
        my $self = shift;
        IO::Socket::INET->new(
            PeerAddr => $self->stun_server,
            PeerPort => $self->port,
            PeerProto => $self->proto,
            ReuseAddr => 1
        )
    }
);

has 'transaction_id' => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => random_regex('[0-9A-F]{32}')
);

has 'retries' => (
    is => 'rw',
    isa => 'Int',
    default => 5
);

has 'timeout' => (
    is => 'rw',
    isa => 'Float',
    default => 2.0
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

    if ($self->source_address) {
        my $bind_addr = gethostbyname($self->source_address)
            || die "$0: Couldn't bind.\n";
    
        my $bind_sin = sockaddr_in(0, $bind_addr);
        bind(S, $bind_sin) || die "$0: Couldn't bind $!\n";
    }

    my $iaddr = gethostbyname($self->stun_server);
    my $sin = sockaddr_in($self->port, $iaddr);
    my $transaction_id = $self->transaction_id;

    my $msg = pack('nna[16]',
                0x0001, # Binding Request
                0, # message length excluding header
                $transaction_id
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
                    $msg);

        my $ret = { 
            r_message_type => $r_message_type,
            r_message_length => $r_message_length,
            r_transaction_id => $r_transaction_id,
            r_attr_type => $r_attr_type,
            r_attr_length => $r_attr_length,
            r_ma_dummy => $r_ma_dummy,
            r_ma_family => $r_ma_family,
            r_ma_port => $r_ma_port,
            r_ma_address => $r_ma_address
        };
        return $ret;
    }
}


1;
