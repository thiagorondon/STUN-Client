
package STUN::Status;

use strict;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(status_message);
$VERSION='0.01';

my %status_code = (
    '0001'  => 'BindRequestMsg'
);

sub status_message ($) { $status_code{$_[0]};
