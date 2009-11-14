#!/usr/bin/perl

BEGIN {
    push @INC, './lib/';
}

use STUN::Client;
use Data::Dumper;

$stun_client = STUN::Client->new;

$stun_client->stun_server('stun.ekiga.net');
$stun_client->source_address('192.168.1.247');
$r = $stun_client->run;

print Dumper($r);

